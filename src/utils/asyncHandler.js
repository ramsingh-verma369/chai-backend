// we can use requestHandler or fxn or whatever fnx_name
const asyncHandler = (requestHandler) => {
    (req,res,next) => {
        Promise.resolve(requestHandler(req,res,next)).catch((err) => next(err))
    }
}

export  {asyncHandler}


// const asyncHandler = () => {}
// const asyncHandler = (fn) => () => {}
// const asyncHandler = (fn) => async () => {}

// const asyncHandler = (fn) => async (req, res, next) => {
//     try {
//         await fn(req,res,next);
//     } catch (err) {
//         res.status(err.code || 500).json({
//             success: true,
//             message: err.message
//         })
//     }
// }


