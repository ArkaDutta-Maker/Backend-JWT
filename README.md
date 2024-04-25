# IEEE-JU
This is the backend API of the IEEE-JU Backend JWT Auth Task.
  This was used to authenicate users with JWT token in the frontend.
## Hookup with Frontend
To view the frontend application github visit [here](https://github.com/ArkaDutta-Maker/Frontend-Form).
For the deployed website showcasing and integrating the JWT authenication visit [here](https://frontend-form-2vk3.onrender.com/) 
# Backend-JWT

## Description
This project is a backend service that uses JSON Web Tokens (JWT) for authentication. It is designed to provide secure and efficient authentication for the applications.

## Features
- User Registration
- User Login
- User Update Details
- JWT Authentication
- Refreshing Token automatically after expiry 
- Secure password hashing
- JWT Token Blocklisting using Redis Storage

## Technologies Used
- Flask
- Redis
- Postgresql
- Bcrypt

## Installation
1. Clone the repository: `git clone https://github.com/ArkaDutta-Maker/Backend-JWT.git`
2. Navigate to the project directory: `cd Backend-JWT`
3. Install dependencies: `pip install -r requirements.txt`
4. Set the environment variables as required
5. Start the server: `flask run`

## Usage
After starting the server, you can use the following endpoints:
- `/register`: To register a new user.
- `/login`: To login a user.
- `/user`: To get the user profile (requires JWT token).
- `/refresh`: To refresh expired access token with provided refresh token.
- `/user/update`: To Update User details
