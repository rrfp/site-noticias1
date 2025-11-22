import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import bcrypt from "bcryptjs";
import User from "./models/User.js";

export default function setupPassport() {

    /* ==============================
       🔐 LOCAL STRATEGY
    =============================== */
    passport.use(
        new LocalStrategy(
            { usernameField: "email" },
            async (email, password, done) => {
                try {
                    const user = await User.findOne({ email });

                    if (!user) {
                        return done(null, false, { message: "Usuário não encontrado" });
                    }

                    const isMatch = await bcrypt.compare(password, user.password);
                    if (!isMatch) {
                        return done(null, false, { message: "Senha incorreta" });
                    }

                    return done(null, user);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );

    /* ==============================
       🔐 GOOGLE STRATEGY
    =============================== */
    passport.use(
        new GoogleStrategy(
            {
                clientID: process.env.GOOGLE_CLIENT_ID,
                clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                callbackURL: process.env.GOOGLE_CALLBACK_URL, // MUITO IMPORTANTE
            },
            async (accessToken, refreshToken, profile, done) => {
                try {
                    let user = await User.findOne({ googleId: profile.id });

                    if (!user) {
                        user = await User.create({
                            googleId: profile.id,
                            username: profile.displayName,
                            email: profile.emails[0].value,
                        });
                    }

                    return done(null, user);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );

    /* ==============================
       🔐 GITHUB STRATEGY
    =============================== */
    passport.use(
        new GitHubStrategy(
            {
                clientID: process.env.GITHUB_CLIENT_ID,
                clientSecret: process.env.GITHUB_CLIENT_SECRET,
                callbackURL: process.env.GITHUB_CALLBACK_URL, // MUITO IMPORTANTE
            },
            async (accessToken, refreshToken, profile, done) => {
                try {
                    let user = await User.findOne({ githubId: profile.id });

                    if (!user) {
                        user = await User.create({
                            githubId: profile.id,
                            username: profile.username,
                            email: profile.emails?.[0]?.value || `${profile.username}@github.com`,
                        });
                    }

                    return done(null, user);
                } catch (error) {
                    return done(error);
                }
            }
        )
    );

    /* ==============================
       🔐 SESSÕES
    =============================== */
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user);
        } catch (error) {
            done(error, null);
        }
    });
}
