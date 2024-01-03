import Users from "../models/userModel.js";
import { compareString, createJWT, hashString } from "../utils/index.js";
import { sendVerificationEmail } from "../utils/sendEmail.js";

export const register = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;

  if (!(firstName || lastName || email || password)) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const userExist = await Users.findOne({ email });
    if (userExist) {
      return res.status(400).json({ message: "Email Address already exists" });
    }

    const hashedPassword = await hashString(password);
    const user = await Users.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });

    //send email verification link to user
    sendVerificationEmail(user, res);
  } catch (error) {
    console.log(error);
    res.status(404).json({ message: error.message });
  }
};

export const login = async (req, res, next) => {
  const { email, password } = req.body;
    
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    //find user by email
    const user = await Users.findOne({ email }).select("+password").populate({
      path: "friends",
      select: "firstName lastName location profileUrl -password",
    });

    if (!user) {
      next("Invalid Credentials")
      return;
    }

    if (!user?.verified) {
      next("User email is not verified. Check your email to verify your account")
      return; 
    }

    //check if password matches
    const isMatch = await compareString(password, user?.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid Credentials" });
    }

    user.password = undefined;
    const token = createJWT(user?._id);
    res.status(201).json({
      success: true,
      message: "Login successfully",
      user,
      token,
    });
  } catch (error) {
    console.log(error);
    res.status(404).json({ message: error.message });
  }
};
