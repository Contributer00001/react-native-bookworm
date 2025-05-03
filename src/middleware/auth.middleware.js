import jwt from "jsonwebtoken";
import User from "../models/User.js";

// const response = await fetch(`http://localhost:3000/api/books`,{
//     method:"POST",
//     body: JSON.stringify({
//         title,
//         caption
//     }),
//     headers: {
//         Authorization:`Bearer ${token}`
//     },
// })

const protectRoute = async (req, res, next) => {

    try {
        //get token
        const authHeader = req.header("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "Invalid auth header" });
        }
        const token = authHeader.split(" ")[1]; // splits at the space


        if (!token) return res.status(401).json({ message: "No  authentication token, access denied" });

        //verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);


        //FIND USER
        const user = await User.findById(decoded.userId).select("-password");
        if (!user) return res.status(401).json({ message: "Token is not valid" });

        req.user = user;
        next();




    } catch (error) {
        console.error("Authentication error:", error.message);
        res.status(401).json({ message: "Token is not valid" });
    }
};

export default protectRoute;