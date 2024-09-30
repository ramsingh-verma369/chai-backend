import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { validateEmail } from "../utils/validateEmail.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import mongoose from "mongoose";
import jwt from 'jsonwebtoken';

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = await  user.generateAccessToken();
    const refreshToken =  user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken }
  } catch (error) {
    throw new ApiError(500,"Something went wrong during creating access and refresh token")
  }
}

export const registerUser = asyncHandler(async (req, res) => {
  /*
    user detail from from frontend
    validation -not empty
    check user and email are unique or not
    check for images, check for the avatar
    upload them cloudinary,avatar
    create user object - create entry in db
    remove password and refreshToken field from response
    check for user creation
    return res 
    */
  const { fullName, email, username, password } = req.body;

  if (
    [fullName, email, username, password].some((field) => field?.trim === "")
  ) {
    throw new ApiError(400, "All field are required");
  }

  if (!validateEmail(email)) {
    throw new ApiError(400, "Please enter valid email");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (existedUser) {
    throw new ApiError(409, "User already exist");
  }
  const avatarLocalPath = req.files?.avatar[0]?.path;
//   const coverImageLocalPath = req.files?.coverImage[0]?.path;  //cann give undefined when coverImage is empty
  let coverImageLocalPath;
  if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
    coverImageLocalPath = req.files.coverImage[0].path;
  }
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar local path is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if(!avatar){
    throw new ApiError(400,"Avatar cloudinary response is required")
  }

  const user = await  User.create({
    username: username.toLowerCase(),
    fullName,
    email,
    password,
    avatar: avatar.url,
    coverImage: coverImage?.url || ""
  })

  const createdUser = await User.findById(user._id).select("-password -refreshToken");
  if(!createdUser) {
    throw new ApiError(500,"Error in register controller");
  }
  return res.status(201).json(
    new ApiResponse(200, createdUser, "User registered successfully")
  )

});

export const loginUser = asyncHandler( async (req, res) => {
  /*
  user input 
  find the user
  check password
  create access token and refresh token
  send cookie
  */
  const { username, email, password } = req.body;

  if(!username && !email ){
    throw new ApiError(400,"All fields are required")
  }

  const user = await User.findOne({
    $or: [{ username }, { email }]
  });

  if(!user){
    throw new ApiError(404,"User doesnot exist")
  }
  
  const isValidPassword = await user.isPasswordCorrect(password);
  if(!isValidPassword){
    throw new ApiError(400,"Invalid user credentials")
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

  const options = {
    httpOnly: true,
    secure: true
  }

  return res
  .status(200)
  .cookie("accessToken",accessToken, options)
  .cookie("refreshToken",refreshToken,options)
  .json(
    new ApiResponse(200,
      {
        user: loggedInUser, accessToken, refreshToken
      },
      "User loggedIn successfully"
    )
  )
});

export const logoutUser = asyncHandler (async (req,res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1,  
      }
    },
    {
      new: true,
    }
  )
  const options = {
    httpOnly: true,
    secure: true
  }
  return res
  .status(200)
  .clearCookie("accessToken",options)
  .clearCookie("refreshToken",options)
  .json(new ApiError(200,{},"User logout successfully"))
});

export const refreshTokenAccess = asyncHandler(async (req,res) => {
  try {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    const decodeToken = jwt.verify(
      incomingRefreshToken,
      REFRESH_TOKEN_SECRET
    )

    const user = await User.findById(decodeToken?._id);
    if (!user) {
      throw new ApiError(400,"Invalid refresh token"
      )
    }

    if(incomingRefreshToken !== user?.refreshToken){
      throw new ApiError(401,"Refresh token is already expired")
    }

    const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user?._id);
    
    const options = {
      httpOnly: true,
      secure: true
    }

    return res
    .status(201)
    .cookie("accessToken",accessToken, options)
    .cookie("refreshToken",newRefreshToken, options)
    .json(
      new ApiResponse(
        200,
        { accessToken, refreshToken: newRefreshToken },
        "Access token is refreshed"
      )
    )

  } catch (error) {
    throw new ApiError(401,error?.message || "Invalid refresh token")
  }
})

