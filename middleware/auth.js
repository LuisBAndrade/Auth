import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config()

const authMiddleware = (req, res, next) => {
    const token = req.cookies.access_token

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided'})
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET)

        const currentTime = Math.floor(Date.now() / 1000)
        const timeLeft = decoded.exp - currentTime

        if (timeLeft < 600) {
            const newToken = jwt.sign(
                { userId: decoded.userId, email: decoded.email },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            )

            res.cookie('access_token', newToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60
            })
        }

        req.user = decoded
        next()
    } catch (err) {
        console.error(' JWT verification error:', err)
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Session expired. Please log in again' })
        }
        return res.status(400).json({ error: 'Invalid token' })
    }
}

export default authMiddleware