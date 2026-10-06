import "dotenv/config";

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import router from "./routes/index.js";

const app = express();

app.use(
    cors({
        origin: process.env.FRONTEND_URL,
        credentials: true,
    })
);

app.use(cookieParser());
app.use(express.json());

app.use("/", router);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});