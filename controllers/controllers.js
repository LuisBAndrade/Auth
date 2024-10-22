import { z } from 'zod'
import bcrypt from 'bcrypt'
import client from '../db/db.js'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config()

const userSchema = z.object({
    email: z.string().email({ message: 'Invalid email address' }),
    password: z.string()
        .min(8, { message: 'Password must be at least 8 characters long' })
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, 
            'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
})

const register = async (req, res) => {
    try {
        const useData = userSchema.parse(req.body)
        const { email, password } = userData

        const { rows } = await client.query(
            'SELECT * FROM users WHERE email = $1', [email]
        )
        if (rows.length > 0) {
            return res.status(400).json({ error: 'Email already in use' })
        }

        const hashedPassword = await bcrypt.hash(password, 12)

        const newUser = await client.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email', [email, hashedPassword]
        )
        res.status(201).json({ message: 'User created successfully', user: newUser.rows[0] })
    } catch (err) {
        if (err instanceof z.ZodError) {
            res.status(400).json({ error: err.errors })
        } else {
            console.error('User creation error:', err.message)
            res.status(500).json({ error: 'An error ocurred during user creation'})
        }
    }
}

const login = async (req, res) => {
    try {
        const userData = userSchema.parse(req.body)
        const { email, password } = userData

        const existingUser = await client.query(
            'SELECT * FROM users WHERE email = $1', [email]
        )

        if (existingUser.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' })
        }

        const user = existingUser.rows[0]
        const isValid = await bcrypt.compare(password, user.password)

        if (!isValid) {
            return res.status(401).json({ error: 'Invalid email or password' })
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiredIn: '1h' }
        )

        res.cookie('access_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            MAXaFE: 1000 * 60 * 60
        })

        res.status(200).json({ message: 'login successful' })
    } catch (err) {
        if (err instanceof z.ZodError) {
            res.status(400).json({ error: err.errors })
        }
        console.error('Login error:', err.message)
        return res.status(500).json({ error: 'An error ocurred during login'})
    }
}

const logout = async (req, res) => {
    res.clearCookie('access_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    })

    res.status(200).json({ message: 'logout successfully' })
}

const profile = async (req, res) => {
    const userEmail = req.user.email
    res.send(`Hello, ${userEmail}`)
}

export { register, login, logout, profile}