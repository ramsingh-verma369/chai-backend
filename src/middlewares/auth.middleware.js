import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js"

// when any field in unused then eg: res(unused) -> -
export const verifyJWT = asyncHandler(async (req,_,next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization").replace("Bearer ","");
        if(!token) {
            throw new ApiError(400,"Unauthoraized token")
        }
    
        const decodeToken = jwt.verify(token,process.env.REFRESH_TOKEN_SECRET);
    
        const user = await User.findById(decodeToken?._id).select("-password -refreshToken");
        if(!user) {
            throw new ApiError(401,"Invalid accessToken")
        }
        
        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid Access Token");
    }
})