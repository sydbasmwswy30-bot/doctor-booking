// security.js
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const router = express.Router();
const SECRET_KEY = "SECRET_KEY_خیلی_سخت"; // تغییر بده به یه رشته قوی

// هش کردن پسورد قبل ذخیره
export async function hashPassword(password){
    const saltRounds = 12; // امنیت بالا
    return await bcrypt.hash(password, saltRounds);
}

// مقایسه پسورد وارد شده با هش شده
export async function comparePassword(password, hashedPassword){
    return await bcrypt.compare(password, hashedPassword);
}

// ایجاد توکن JWT
export function generateToken(user){
    return jwt.sign({id: user._id, role: user.role}, SECRET_KEY, {expiresIn: "2h"});
}

// middleware اعتبارسنجی توکن
export function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if(!token) return res.status(401).json({error:"دسترسی ندارید"});
    try{
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded; // اطلاعات کاربر در req.user
        next();
    }catch(err){
        return res.status(403).json({error:"توکن نامعتبر"});
    }
}

// نمونه استفاده در Route
router.post("/secure-data", authenticateToken, (req,res)=>{
    res.json({message:"این داده امنه!", user:req.user});
});

export default router;
