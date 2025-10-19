import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
dotenv.config();

// import authentication middleware
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { comparePassword } from "../utils/compare.js";
import { zUserPutBody } from "../libs/zodValidators.js";
import type { Signup } from "../libs/types.js";
import { v4 as uuidv4 } from "uuid";
import { create } from "domain";
const router = Router();
const prisma = new PrismaClient();
// POST /api/v2/auth/signin
router.post("/signin", async (req: Request, res: Response) => {
  try {
    // get username and password from body
    const { username, password } = req.body;
    // const user = users.find(
    //   (u: User) => u.username === username && u.password === password
    // );
    // const user = users.find((u: any) => u.username === username);
    const user = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });
    // if user not found
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Username or Password is incorrect",
      });
    }
    // เพิ่มทีหลัง
    const valid = await comparePassword(password, user.password as string);
    if (!valid) return res.status(401).json({ message: "Invalid password" });
    // create jwt token
    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";
    const token = jwt.sign(
      {
        // create JWT Payload
        username: user.username,
        userId: user.userId,
      },
      jwt_secret,
      { expiresIn: "1h" }
    );

    // store the new token in user.tokens
    // user.tokens = user.tokens ? [...user.tokens, token] : [token];
    // if (!user.tokens) user.tokens = [];
    // user.tokens.push(token);

    return res.status(200).json({
      success: true,
      message: "Sigin successful",
      token,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});
// POST /api/v2/auth/signup
router.post("/signup", async (req: Request, res: Response) => {
  try {
    const body = zUserPutBody.safeParse(req.body);
    
    if (!body.success ) {
      return res.json({
        success: false,
        message: "Validation failed",
        errors: body.error.issues[0]?.message,
      });
    }

    const { 
      firstName, 
      lastName, 
      username, 
      dateOfBirth, 
      password 
    } = body.data;

    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = await prisma.user.create ({
      data: {
        userId: uuidv4(),
        firstName,
        lastName,
        username,
        dateOfBirth,
        password: hashedPassword,
      }
    });

    return res.status(201).json({
      success: true,
      message: "Sign up successful",
      data: {
        userId: newUser.userId,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        username: newUser.username,
        dateOfBirth: newUser.dateOfBirth,
        password: newUser.password, 
        createAt: newUser.createAt,
        updateAt: newUser.updateAt
      }
    });

  } catch(err){
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// POST /api/v2/auth/signout
router.post("/signout", authenticateToken, (req: Request, res: Response) => {
  try {
    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;
