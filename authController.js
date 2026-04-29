const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const userModel = require("../models/userModel")

/* ===============================
   REGISTER USER
================================ */

exports.registerUser = async (req, res, next) => {

  try {

    const { name, email, password } = req.body

    const hashedPassword = await bcrypt.hash(password, 10)

    const user = await userModel.createUser({
      name,
      email,
      password: hashedPassword
    })

    res.status(201).json(user)

  } catch (error) {
    next(error)
  }

}

/* ===============================
   LOGIN USER
================================ */

exports.loginUser = async (req, res, next) => {

  try {

    const { email, password } = req.body

    const user = await userModel.getUserByEmail(email)

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password
    )

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    )

    res.json({ token, user })

  } catch (error) {
    next(error)
  }

}

/* ===============================
   GET PROFILE
================================ */

exports.getProfile = async (req, res, next) => {

  try {

    const user = await userModel.getUserById(req.user.id)

    res.json(user)

  } catch (error) {
    next(error)
  }

}