const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const session = require("express-session");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
require("dotenv").config();
// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

// Define a user schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  profilePicture: String,
  resetToken: String,
  resetTokenExpires: Date,
  verified: { type: Boolean, default: false }, // Add a 'verified' field to the user model and set it to false by default
  verificationToken: String, // Add a field to store the verification token
  verificationTokenExpires: Date, // Add a field to store the expiration time of the verification token
});

// Create a user model
const User = mongoose.model("User", userSchema);

// Define a form schema
const formSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
});

// Create a form model
const Form = mongoose.model("Contact-Data", formSchema);

// Define a testimonial schema
const testimonialSchema = new mongoose.Schema({
  author: String,
  testimonialText: String,
  testimonialImage: String,
  authorProfilePicture: String,
});

// Create a testimonial model
const Testimonial = mongoose.model("Testimonial", testimonialSchema);

// Create an Express.js app
const app = express();

// Create the "uploads" directory if it doesn't exist
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Create a multer storage configuration for profile picture uploads
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: function (req, file, cb) {
    cb(null, "profile-" + Date.now() + path.extname(file.originalname));
  },
});

// Initialize multer with the storage configuration
const upload = multer({ storage: storage });

// Set 'ejs' as the view engine
app.set("view engine", "ejs");

// Set the views directory to the current directory (where app.js is located)
app.set("views", path.join(__dirname));

// Render the home page
app.get("/", (req, res) => {
  res.redirect("/home");
});

// Render the account page
app.get("/account", (req, res) => {
  res.render("account");
});

// Parse request bodies
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Serve static files (e.g., your HTML, CSS, and client-side JavaScript)
app.use(express.static(__dirname + "/"));

// Configure session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    // Add a session store (e.g., connect-mongo) based on your requirements
  })
);

// Configure password reset email service
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});
// Handle signup POST request
app.post("/signup", (req, res) => {
  const { signupUsername, signupEmail, signupPassword } = req.body;

  if (
    !signupUsername ||
    !signupEmail ||
    !signupPassword ||
    signupPassword.length < 8
  ) {
    console.log("Invalid input");
    return res.status(400).send("Invalid input");
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(signupEmail)) {
    console.log("Invalid email");
    return res.status(400).send("Invalid email");
  }

  User.findOne({ $or: [{ username: signupUsername }, { email: signupEmail }] })
    .then((existingUser) => {
      if (existingUser) {
        console.log("Username or email already exists");
        res.status(409).send("Username or email already exists");
      } else {
        bcrypt.hash(signupPassword, 10, (err, hashedPassword) => {
          if (err) {
            console.error("Failed to hash password:", err);
            res.status(500).send("Failed to create user");
          } else {
            const verificationToken = crypto.randomBytes(20).toString("hex");
            const user = new User({
              username: signupUsername,
              email: signupEmail,
              password: hashedPassword,
              verified: false,
              verificationToken: verificationToken,
              verificationTokenExpires: Date.now() + 3600000, // Token expires in 1 hour
            });

            user
              .save()
              .then(() => {
                console.log("User created:", user);
                const mailOptions = {
                  from: process.env.EMAIL_USERNAME,
                  to: user.email,
                  subject: "Account Verification",
                  text: `Hello ${user.username},\n\nThank you for signing up. Please click on the following link to verify your account:\n\nhttps://brainsnap.onrender.com/verify-account?token=${verificationToken}\n\nThis token will expire in 1 hour. If you did not sign up for an account, please ignore this email.\n\nBest regards,\nThe Team`,
                };

                transporter.sendMail(mailOptions, (error, info) => {
                  if (error) {
                    console.error("Failed to send verification email:", error);
                    res.status(500).send("Failed to send verification email");
                  } else {
                    console.log("Verification email sent:", info.response);
                    res.send(
                      "User created successfully. Please check your email for verification."
                    );
                  }
                });
              })
              .catch((err) => {
                console.error("Failed to create user:", err);
                res.status(500).send("Failed to create user");
              });
          }
        });
      }
    })
    .catch((err) => {
      console.error("Failed to check existing user:", err);
      res.status(500).send("Failed to check existing user");
    });
});

// Handle account verification GET request
app.get("/verify-account", (req, res) => {
  const { token } = req.query;

  User.findOne({ verificationToken: token, verified: false })
    .then((user) => {
      if (user) {
        const now = new Date();
        if (user.verificationTokenExpires > now) {
          user.verified = true;
          user.verificationToken = undefined;
          user.verificationTokenExpires = undefined;

          user
            .save()
            .then(() => {
              console.log("Account verified successfully");
              res.redirect("/account");
            })
            .catch((err) => {
              console.error("Failed to update user:", err);
              res.status(500).send("Failed to verify account");
            });
        } else {
          throw new Error("Invalid or expired verification token");
        }
      } else {
        throw new Error("Invalid or expired verification token");
      }
    })
    .catch((err) => {
      console.error("Account verification failed:", err);
      res.status(400).send("Invalid or expired verification token");
    });
});

// Handle login POST request
app.post("/login", (req, res) => {
  // Get login form data
  const { loginIdentifier, loginPassword, rememberMe } = req.body;

  // Find the user by username or email
  User.findOne({
    $or: [{ username: loginIdentifier }, { email: loginIdentifier }],
  })
    .then((user) => {
      if (user) {
        if (!user.verified) {
          // If the user account is not verified, show a message and don't allow login
          console.log("Please verify your email first.");
          return res.status(401).send("Please verify your email first.");
        }

        // Compare the entered password with the hashed password
        bcrypt.compare(loginPassword, user.password, (err, result) => {
          if (err) {
            console.error("Failed to compare passwords:", err);
            res.status(500).send("Failed to login");
          } else if (result) {
            console.log("User logged in:", user);

            // Set user session upon successful login
            req.session.user = user;

            // Set session expiration (optional)
            if (rememberMe) {
              req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
            }

            // Redirect to the home
            res.redirect("/home");
          } else {
            console.log("Incorrect password");
            res.status(401).send("Incorrect password");
          }
        });
      } else {
        console.log("User does not exist. Please create an account.");
        res.status(404).send("User does not exist. Please create an account.");
      }
    })
    .catch((err) => {
      console.error("Failed to find user:", err);
      res.status(500).send("Failed to find user");
    });
});

// Handle password reset request
app.post("/forgot-password", (req, res) => {
  const { forgotIdentifier, forgotPassword } = req.body;

  // Generate a unique reset token
  const resetToken = crypto.randomBytes(20).toString("hex");
  const resetTokenExpires = Date.now() + 3600000; // Token expires in 1 hour

  // Find the user by username or email
  User.findOne({
    $or: [{ username: forgotIdentifier }, { email: forgotIdentifier }],
  })
    .then((user) => {
      if (user) {
        // Update the user's reset token and expiration time
        user.resetToken = resetToken;
        user.resetTokenExpires = resetTokenExpires;
        return user.save();
      } else {
        throw new Error("User not found");
      }
    })
    .then((updatedUser) => {
      // Send password reset email with the reset token
      const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: updatedUser.email,
        subject: "Password Reset",
        text: `Hello ${updatedUser.username},\n\nYou have requested a password reset. Please click on the following link to reset your password:\n\nhttps://brainsnap.onrender.com/reset-password\n\nYour Token is : ${resetToken}.\n\nThis token will expire in 1 hour. If you did not request a password reset, please ignore this email.\n\nBest regards,\nThe Team`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Failed to send password reset email:", error);
          res.status(500).send("Failed to send password reset email");
        } else {
          console.log("Password reset email sent:", info.response);
          res.send("Password reset email sent");
        }
      });
    })
    .catch((error) => {
      console.error("Error in password reset:", error);
      res.status(404).send("User not found");
    });
});

app.get("/reset-password", (req, res) => {
  res.render("password-reset");
});
// Handle password reset request
app.post("/reset-password", (req, res) => {
  const { newPassword, resetToken } = req.body;

  // Find the user by the reset token
  User.findOne({
    resetToken: resetToken,
    resetTokenExpires: { $gt: Date.now() },
  })
    .then((user) => {
      if (user) {
        // Hash the new password
        bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
          if (err) {
            console.error("Failed to hash password:", err);
            res.status(500).send("Failed to reset password");
          } else {
            // Update the user's password
            user.password = hashedPassword;
            user.resetToken = undefined;
            user.resetTokenExpires = undefined;

            // Save the updated user
            user
              .save()
              .then(() => {
                console.log("Password reset successful");
                res.send("Password reset successful");
              })
              .catch((err) => {
                console.error("Failed to update password:", err);
                res.status(500).send("Failed to reset password");
              });
          }
        });
      } else {
        console.log("Invalid or expired reset token");
        res.status(400).send("Invalid or expired reset token");
      }
    })
    .catch((err) => {
      console.error("Failed to find user:", err);
      res.status(500).send("Failed to find user");
    });
});

// Update the '/home' GET request handler to fetch random testimonials from the database
app.get("/home", (req, res) => {
  // Fetch 5 random testimonials from the database
  Testimonial.aggregate([{ $sample: { size: 5 } }])
    .then((randomTestimonials) => {
      // Select 3 random testimonials to display on the home page
      const displayedTestimonials = randomTestimonials.slice(0, 3);

      // Get the user's profile picture URL, username, and email from the session (if available)
      const profilePictureURL = req.session.user
        ? req.session.user.profilePicture
        : null;
      const username = req.session.user ? req.session.user.username : null;
      const email = req.session.user ? req.session.user.email : null;

      // Render the home page (index.ejs) and pass the displayed testimonials, profile picture URL, username, and email to the template
      res.render("index", {
        testimonials: displayedTestimonials,
        profilePictureURL,
        username,
        email,
      });
    })
    .catch((err) => {
      console.error("Failed to fetch random testimonials:", err);
      res.status(500).send("Failed to fetch random testimonials");
    });
});

// Handle logout GET request
app.get("/logout", (req, res) => {
  // Clear the user session
  req.session.destroy((err) => {
    if (err) {
      console.error("Failed to destroy session:", err);
    } else {
      console.log("Logout sucessfull!");
    }
    // Redirect to the login page
    res.redirect("/");
  });
});

// Update the '/profile' GET request handler to pass the profile picture URL
app.get("/profile", (req, res) => {
  // Check if the user is authenticated (e.g., session-based authentication)
  if (req.session && req.session.user) {
    // Render the 'profile' EJS template and pass the username, email, and profilePictureURL to the template
    res.render("profile", {
      username: req.session.user.username,
      email: req.session.user.email,
      profilePictureURL: req.session.user.profilePicture, // Replace "/default-profile-picture.jpg" with the default profile picture URL
    });
  } else {
    // User is not authenticated, redirect to login page
    res.redirect("/");
  }
});

// Update the '/profile' GET request handler to pass the profile picture URL
app.get("/edit-profile", (req, res) => {
  // Check if the user is authenticated (e.g., session-based authentication)
  if (req.session && req.session.user) {
    // Render the 'profile' EJS template and pass the username, email, and profilePictureURL to the template
    res.render("update-profile", {
      username: req.session.user.username,
      email: req.session.user.email,
      profilePictureURL: req.session.user.profilePicture, // Replace "/default-profile-picture.jpg" with the default profile picture URL
    });
  } else {
    // User is not authenticated, redirect to login page
    res.redirect("/");
  }
});

// Update the '/submit-testimonial' GET request handler to check for authentication
app.get("/submit-testimonial", (req, res) => {
  // Check if the user is authenticated (e.g., session-based authentication)
  if (req.session && req.session.user) {
    const username = req.session.user ? req.session.user.username : null;
    // User is authenticated, render the 'submitTestimonial' page
    res.render("add-testimonial", { username });
  } else {
    // User is not authenticated, redirect to the login page or another page of your choice
    res.redirect("/account"); // Replace "/login" with the URL of your login page
  }
});

// Update the '/update-profile' POST request handler to handle profile updates and update session data
app.post("/update-profile", upload.single("profilePicture"), (req, res) => {
  // Get update profile form data
  const { newUsername, newEmail } = req.body;

  // Check if the user is authenticated (e.g., session-based authentication)
  if (req.session && req.session.user) {
    // Find the user by the session data
    User.findById(req.session.user._id)
      .then((user) => {
        if (user) {
          // Update the user's profile information
          if (newUsername) {
            user.username = newUsername;
          }
          if (newEmail) {
            user.email = newEmail;
          }
          if (req.file) {
            // If a profile picture was uploaded, save the file path in the database
            user.profilePicture = req.file.filename;
          }

          // Save the updated user
          user
            .save()
            .then((updatedUser) => {
              // Update the session data with the new profile information
              req.session.user = {
                _id: updatedUser._id,
                username: updatedUser.username,
                email: updatedUser.email,
                profilePicture: updatedUser.profilePicture,
              };

              console.log("Profile updated successfully");
              res.send("Profile updated successfully");
            })
            .catch((err) => {
              console.error("Failed to update profile:", err);
              res.status(500).send("Failed to update profile");
            });
        } else {
          console.log("User not found");
          res.status(404).send("User not found");
        }
      })
      .catch((err) => {
        console.error("Failed to find user:", err);
        res.status(500).send("Failed to find user");
      });
  } else {
    // User is not authenticated, redirect to login page
    res.redirect("/account");
  }
});

// Handle the contact form POST request
app.post("/contact", (req, res) => {
  const { name, email, message } = req.body;

  // Input validation
  if (!name || !email || !message) {
    console.log("Invalid input");
    return res.status(400).send("Invalid input");
  }

  // Create a new form entry with the provided data
  const formEntry = new Form({
    name: name,
    email: email,
    message: message,
  });

  // Save the form entry to the database
  formEntry
    .save()
    .then(() => {
      console.log("Form entry saved:", formEntry);
      res.send("Form entry saved successfully");
    })
    .catch((err) => {
      console.error("Failed to save form entry:", err);
      res.status(500).send("Failed to save form entry");
    });
});

// Handle the request to delete the profile picture
app.get("/delete-profile-picture", (req, res) => {
  // Check if the user is authenticated (e.g., session-based authentication)
  if (req.session && req.session.user) {
    // Find the user by the session data
    User.findById(req.session.user._id)
      .then((user) => {
        if (user) {
          // Remove the profile picture from the filesystem (if exists)
          const profilePicturePath = path.join(uploadsDir, user.profilePicture);
          if (fs.existsSync(profilePicturePath)) {
            fs.unlinkSync(profilePicturePath);
          }

          // Remove the profile picture from the database
          user.profilePicture = undefined;

          // Save the updated user
          user
            .save()
            .then(() => {
              console.log("Profile picture deleted successfully");
              // Update the profile picture URL in the session
              req.session.user.profilePicture = undefined;
              // Redirect to the profile page or any other page you prefer
              res.redirect("/profile");
            })
            .catch((err) => {
              console.error("Failed to delete profile picture:", err);
              res.status(500).send("Failed to delete profile picture");
            });
        } else {
          console.log("User not found");
          res.status(404).send("User not found");
        }
      })
      .catch((err) => {
        console.error("Failed to find user:", err);
        res.status(500).send("Failed to find user");
      });
  } else {
    // User is not authenticated, redirect to login page
    res.redirect("/");
  }
});

// Handle the request to delete the full account
app.get("/delete-account", (req, res) => {
  // Check if the user is authenticated (e.g., session-based authentication)
  if (req.session && req.session.user) {
    // Find the user by the session data
    User.findOneAndRemove({ username: req.session.user.username })
      .then((user) => {
        if (user) {
          // If the user uploaded a profile picture, remove it from the filesystem
          if (user.profilePicture) {
            const profilePicturePath = path.join(
              uploadsDir,
              user.profilePicture
            );
            if (fs.existsSync(profilePicturePath)) {
              fs.unlinkSync(profilePicturePath);
            }
          }

          console.log("Account deleted successfully");
          // Clear the user session after deleting the account
          req.session.destroy((err) => {
            if (err) {
              console.error("Failed to destroy session:", err);
            }
            // Redirect to the home page (or wherever you want to redirect after deleting the account)
            res.redirect("/home");
          });
        } else {
          console.log("User not found");
          res.status(404).send("User not found");
        }
      })
      .catch((err) => {
        console.error("Failed to delete account:", err);
        res.status(500).send("Failed to delete account");
      });
  } else {
    // User is not authenticated, redirect to login page
    res.redirect("/");
  }
});

app.post(
  "/submit-testimonial",
  upload.single("testimonialImage"),
  (req, res) => {
    const { author, testimonialText } = req.body;

    // Input validation
    if (!author || !testimonialText) {
      console.log("Invalid input");
      return res.status(400).send("Invalid input");
    }

    // Check if the user is authenticated (e.g., session-based authentication)
    if (req.session && req.session.user) {
      // Find the user by the session data
      User.findById(req.session.user._id)
        .then((user) => {
          if (user) {
            // Create a new testimonial entry with the provided data
            const testimonial = new Testimonial({
              author: author,
              testimonialText: testimonialText,
            });

            // If the user uploaded a profile picture, save the filename in the testimonial entry
            if (user.profilePicture) {
              testimonial.authorProfilePicture = user.profilePicture;
            }

            // If a testimonial image was uploaded, save the filename in the testimonial entry
            if (req.file) {
              testimonial.testimonialImage = req.file.filename;
            }

            // Save the testimonial to the database
            return testimonial.save();
          } else {
            throw new Error("User not found");
          }
        })
        .then(() => {
          console.log("Testimonial saved successfully");
          res.redirect("/home");
        })
        .catch((err) => {
          console.error("Failed to save testimonial:", err);
          res.status(500).send("Failed to save testimonial");
        });
    } else {
      // If the user is not authenticated, create the testimonial without user-related data
      const testimonial = new Testimonial({
        author: author,
        testimonialText: testimonialText,
      });

      // If a testimonial image was uploaded, save the filename in the testimonial entry
      if (req.file) {
        testimonial.testimonialImage = req.file.filename;
      }

      // Save the testimonial to the database
      testimonial
        .save()
        .then(() => {
          console.log("Testimonial saved successfully");
          res.redirect("/home");
        })
        .catch((err) => {
          console.error("Failed to save testimonial:", err);
          res.status(500).send("Failed to save testimonial");
        });
    }
  }
);

// Render the colleges page (accessible only after login)
app.get("/colleges", (req, res, next) => {
  // Check if the user is authenticated
  if (req.session && req.session.user) {
    // Get the user's profile picture URL, username, and email from the session
    const profilePictureURL = req.session.user.profilePicture;
    const username = req.session.user.username;
    const email = req.session.user.email;

    // Render the "colleges" page and pass the user data to the template
    res.render("colleges", { username, email, profilePictureURL });
  } else {
    // If the user is not logged in, redirect to the login page (or any other page you prefer)
    res.redirect("/account");
  }
});

// Start the server
app.listen(process.env.PORT, () => {
  console.log("Server is running on port 3000");
});
