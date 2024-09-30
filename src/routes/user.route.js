import { Router } from "express";
import { loginUser, logoutUser, refreshTokenAccess, registerUser } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js"
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route('/register').post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",  // this name is same as frontend
            maxCount: 1
        }
    ]),
    registerUser);

router.route('/login').post(loginUser);

router.route('/logout').post(verifyJWT, logoutUser);

router.route('/refresh-token').post(refreshTokenAccess);


export default router;