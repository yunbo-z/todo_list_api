const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
require('dotenv').config()

app.use(express.json())

const port = process.env.TOKEN_SERVER_PORT

const users = []

// accessTokens
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" })
}
// refreshTokens
let refreshTokens = []
function generateRefreshToken(user) {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "20m" })
    refreshTokens.push(refreshToken)
    return refreshToken
}

app.post("/createuser", async (req, res) => {
    const user = req.body.name
    const hashedPassword = await bcrypt.hash(req.body.password, 10)

    users.push({
        user,
        password: hashedPassword
    })

    res.status(201).send(users)
    console.log(users)
})
app.post("/login", async () => {
    const user = users.find((userInfo) => userInfo.user == req.body.name)
    if (user == null) {
        res.status(404).send("User does not exist")
    }
    const isPSCorrect = await bcrypt.compare(req.body.password, user.password)
    if (isPSCorrect) {
        const accessToken = generateAccessToken({ user: req.body.name })
        const refreshToken = generateRefreshToken({ user: req.body.name })
        res.json({
            accessToken,
            refreshToken
        })
    } else {
        res.status(401).send("Password Incorrect!")
    }
})

app.listen(port, () => {
    console.log(`Authentication server is running on ${port}...`)
})