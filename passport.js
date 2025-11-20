const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');
const User = require('./models/User');

module.exports = function(passport) {

  // ---- LOGIN LOCAL ----
  passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) return done(null, false, { message: 'Usuário não encontrado' });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return done(null, false, { message: 'Senha incorreta' });

      return done(null, user);
    } catch (err) {
      console.error("Erro login local:", err);
      return done(err);
    }
  }));

  // ---- LOGIN GOOGLE ----
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log("Google profile:", profile);

      const email = (profile.emails && profile.emails.length > 0) 
        ? profile.emails[0].value 
        : null;

      if (!email) {
        console.error("Google login sem email disponível!");
        return done(null, false, { message: "Email não disponível no Google" });
      }

      let user = await User.findOne({ googleId: profile.id });
      if (user) return done(null, user);

      let existingUser = await User.findOne({ email });
      if (existingUser) {
        existingUser.googleId = profile.id;
        await existingUser.save();
        return done(null, existingUser);
      }

      user = new User({
        googleId: profile.id,
        name: profile.displayName || email,
        email
      });

      await user.save();
      return done(null, user);

    } catch (err) {
      console.error("Erro estratégia Google:", err);
      done(err, null);
    }
  }));

  // ---- LOGIN GITHUB ----
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope: ['user:email']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log("GitHub profile:", profile);

      let email = (profile.emails && profile.emails.length > 0)
        ? profile.emails[0].value
        : `${profile.username || profile.id}@users.noreply.github.com`;

      let user = await User.findOne({ githubId: profile.id });
      if (user) return done(null, user);

      let existingUser = await User.findOne({ email });
      if (existingUser) {
        existingUser.githubId = profile.id;
        await existingUser.save();
        return done(null, existingUser);
      }

      user = new User({
        githubId: profile.id,
        name: profile.username || profile.displayName || email,
        email
      });

      await user.save();
      return done(null, user);

    } catch (err) {
      console.error("Erro estratégia GitHub:", err);
      done(err, null);
    }
  }));

  // ---- SERIALIZE / DESERIALIZE ----
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });
};
