import e, { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "@repo/backend-common/config";

interface jwtPayload {
    userId: string;
}
export function middleware(req:Request, res:Response, next:NextFunction) {
    const token = req.headers["authorization"] ?? "";
    const decoded = jwt.verify(token, JWT_SECRET) as jwtPayload
    if(decoded){
        req.userId = decoded.userId;
        next();
    }else{
        res.status(401).json({message:"Unauthorized"});
    }
}