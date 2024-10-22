import express from 'express'
import { login, logout, register, profile } from '../controllers/controllers'
import client from '../db/db'
import rateLimit from 'express-rate-limit'
import authMiddleware from '../middleware/auth'

const router = express.Router()

const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 5
})

router.post('/register', register)
router.post('/login', loginLimiter, login)
router.post('/logout', logout)

router.get('/profile', authMiddleware, profile)

export default router
