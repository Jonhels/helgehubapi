require("dotenv").config();
const express = require("express");
const dbConnect = require("./config/dbConnect");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const logger = require("morgan");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");


// Import routes from the routes folder
const userRoutes = require("./routes/userRoute");

// const route = require("./routes/route");
const app = express(); // Create an express app
app.use(logger("tiny")); // Log http request to the console
app.use(helmet()); // Secure the app through different HTTP headers

// Parse incoming requests to JSON
app.use(bodyParser.json());
// {}
// Connect to the database and start the server
dbConnect().then(() => {
    const PORT = process.env.PORT || 4000;
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);  
    });
});

// cors
const whitelist = ["https://skjaerstein.com", process.env.FRONTEND_URL] // Array of allowed origins
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) {
            // Explicitly block requests with no Origin header
            console.error("CORS Error: Missing Origin header");
            callback(new Error("Access denied. Missing Origin header."));
        } else if (whitelist.includes(origin)) {
            // Allow whitelisted origins
            callback(null, true);
        } else {
            // Block other origins
            console.error(`CORS Error: Origin ${origin} not allowed`);
            callback(new Error("Access denied. Origin not allowed by CORS."));
        }
    },
    credentials: true,
};



// Routes
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "templates", "index.html"));
});

// Template routes
app.use("/api/users", cors(corsOptions), userRoutes);

// Simplified error to user
app.use((err, req, res, next) => {
    if (err.message.includes("CORS")) {
        // Return simplified error for CORS
        return res.status(403).json({ error: "Access denied by CORS policy." });
    }
    // For other errors, log the stack trace and return a generic message
    console.error(err.stack);
    res.status(500).json({ error: "An internal server error occurred." });
});


// Shutdown gracefully
const gracefulShutdown = async () => {
    console.log("Shutting down gracefully...");
    await mongoose.connection.close();
    console.log("MongoDB connection closed");
    process.exit(0);
};

process.on("SIGINT", gracefulShutdown); // Listen for ctrl+C
process.on("SIGTERM", gracefulShutdown); // Listen for the SIGTERM (process manager shutdown process)