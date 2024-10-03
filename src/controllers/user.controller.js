import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { validateEmail } from "../utils/validateEmail.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
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
    if (!incomingRefreshToken) {
      throw new ApiError(401,"unauthoriazed request");
    }

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
});

export const changeCurrentPassword =  asyncHandler( async(req,res) => {
  try {
    const { oldPassword, newPassword, confPassword } = req.body;
    
    if(
      [oldPassword, newPassword, confPassword].some((field) => field?.trim ==="")
    ){
      throw new ApiError(400,"All fields are required")
    }

    if(!(newPassword !== confPassword)){
      throw new ApiError(401,"Password doesnot match")
    }
    const user = await User.findById(req.user?._id);
    const isValidPassword = await user.isPasswordCorrect(oldPassword);
    if(!isValidPassword){
      throw new ApiError(400,"Invalid old password")
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(
      new ApiResponse(200,{},"Password change successfully")
    )
  
  } catch (error) {
    return res
    .status(500)
    .json(
      new ApiError(500,error?.message || "Internal Server Error")
    )
  }
});

export const getCuurentUser = asyncHandler( async(req,res) => {
  return res
  .status(200)
  .json(
    new ApiResponse(200,req.user,"current user fetched successfully")
  )
})

export const updateAccountDetails = asyncHandler( async(req,res) => {
  try {
    const { email, fullName } = req.body;
    if(!fullName || !email){
      throw new ApiError(400,"All fields are required")
    }

    const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          fullName,
          email
        }
      },
      {new: true}  //after update all information will show
    ).select("-password")

    return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        user,
        "Account details updated successfully"
      )
    )
    
  } catch (error) {
    return res
    .status(500)
    .json(
      new ApiError(500, error?.message || "Error in updatedAccountDeatail controller")
    )
  }
})

// delete old image - assignment

export const updateUserAvatar = asyncHandler( async(req,res) => {
  try {
    const avatarLocalPath = req.file?.path;
    if (!avatarLocalPath) {
      throw new ApiError(400,"Avatar file is missing")
    }
  
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if (!avatar) {
      throw new ApiError(400,"Error while uploading on avatar")
    }
  
    const user = await findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          avatar: avatar?.url
        }
      },
      {new: true}
    ).select("-password")
  
    return res
    .status(201)
    .json(
      new ApiResponse(201, user ,"avatar updated successfully")
    )
  } catch (error) {
    new ApiError(500,"Error when updation avatar")
  }
})

export const updatedCoverImage = asyncHandler( async(req,res) => {
  try {
    const coverImageLocalPath = req.file?.path;
    if(!coverImageLocalPath){
      throw new ApiError(400,"coverImage file is missing")
    }
  
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if (!coverImage.url) {
      throw new ApiError(400,"error while uploading avatar")
    }
  
    const user = await findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          coverImage: coverImage?.url
        }
      },
      {new: true}
    )
  
    return res
    .status(201)
    .json(
      new ApiResponse(200, user, "coverImage updated successfully")
    )
  } catch (error) {
    return res
    .status(500)
    .json(
      new ApiError(500,"Error in updated cover image controller")
    )
  }
})

export const getUserChannelProfile = asyncHandler( async(req,res) => {
  const { username } = req.params;
  if(!username?.trim()){
    throw new ApiError(400,"Username is missing");
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase()
      }
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers"
      }     
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: subscribedTo
      }
    },
    {
      $addFields: {
        subscriberCount: {
          $size: "$subscribers"
        },
        channelSubscribedToCount: {
          $size: "$subscribedTo"
        },
        isSubscribed: {
          $cond: {
            if: { $in: [req.user?._id, "$subscribers.subscriber"]},
            then: true,
            else: false
          }
        }
      }
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        subscriberCount: 1,
        channelSubscribedToCount: 1,
        isSubscribed: 1,
        coverImage: 1,
        avatar: 1,
        email: 1
      }
    }
  ])

  if(!channel?.length) {
    throw new ApiError(404,"Channel does not exists")
  }
  return res
  .status(200)
  .json(
    new ApiResponse(200, channel[0], "User channel fetched successfully")
  )
})