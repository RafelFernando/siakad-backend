import express from 'express';
import { getUsers, Register, Login, Logout } from '../controller/auth';
import { verifyToken } from '../middleware/verifyToken';
import { RefreshToken } from '../controller/refreshToken';

const router = express.Router();

router.get('/users', verifyToken, getUsers);
router.post('/users', Register);
router.post('/login', Login);
router.get('/token', RefreshToken);
router.delete('/logout', Logout);

export default router;