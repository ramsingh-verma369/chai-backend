import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";


dotenv.config();

const PORT = process.env.PORT || 8000;

connectDB()
.then(() => {
    app.listen(PORT,() => {
        console.log(`Server is running on the ${PORT}`)
    })

    app.on("ERRR",(error) => {
        console.log("Error",error);
        throw error;
    })
})
.catch((err) => {
    console.log("MongoDB connection is failed",err);
})





// import express from 'express';
// const app = express();

// ( async () => {
//     try {
//         await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
//         app.on("error", (error) => {
//             console.log("ERRR: ", error);
//             throw error;
//         })

//         app.listen(process.env.PORT,() => {
//             console.log(`App is listening on the port ${process.env.PORT}`)
//         })
//     } catch (error) {
//         console.error("ERROR: ",error);
//         throw err;
//     }
// })()