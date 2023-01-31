const express = require("express");
const app = express();
const csrf = require("tiny-csrf");
const cookieParser = require("cookie-parser");
const { AdminCreate,
        election,
        options,
        question,
        voter,
      Answers } = require("./models");
const bodyParser = require("body-parser");
const path = require("path");
app.use(express.static(path.join(__dirname, "/public")));
const bcrypt = require("bcrypt");
const passport = require("passport");
const connectEnsureLogin = require("connect-ensure-login");
const session = require("express-session");
const flash = require("connect-flash");
const LocalStratergy = require("passport-local");
const saltRounds = 10;
app.set("views", path.join(__dirname, "views"));
app.use(flash());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("Some secret String"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));
app.use(
  session({
    secret: "my-super-secret-key-2837428907583420",
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use((request, response, next) => {
  response.locals.messages = request.flash();
  next();
});
app.use(passport.initialize());
app.use(passport.session());
passport.use(
  "admin",
  new LocalStratergy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      AdminCreate.findOne({ where: { email: username } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Invalid Password" });
          }
        })
        .catch(function () {
          return done(null, false, { message: "Unrecognized Email" });
        });
    }
  )
);

passport.use(
  "voter",
  new LocalStratergy(
    {
      usernameField: "voterUnqid",
      passwordField: "voterUnqPswd",
    },
    (username, password, done) => {
      voter.findOne({ where: { voterUnqid: username } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.voterUnqPswd);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Invalid Password" });
          }
        })
        .catch(function () {
          return done(null, false, { message: "Unrecognized UserID" });
        });
    }
  )
);
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});
app.set("view engine", "ejs");
app.get("/", (request, response) => {
  if (request.user) {
    return response.redirect("/election");
  } else {
    response.render("index", {
      title: "Online Voting Platform",
    });
  }
});
app.get(
  "/election",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      let username = request.user.firstName +" "+ request.user.lastName;
      try {
        const elections = await election.getElections(request.user.id);
        if (request.accepts("html")) {
          response.render("election", {
            title: "Online Voting Platform",
            username,
            elections,
            csrfToken: request.csrfToken(),
          });
        } else {
          return response.json({
            elections,
          });
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } 
);
app.get("/signup", (request, response) => {
  response.render("signup", {
    title: "Admin Create a new account",
    csrfToken: request.csrfToken(),
  });
});
app.get("/login", (request, response) => {
  response.render("login", {
    title: "Login to your account",
    csrfToken: request.csrfToken(),
  });
});
app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) {
      return next(err);
    }
    response.redirect("/");
  });
});
app.post(
  "/session",
  passport.authenticate("admin", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (request, response) => {
    response.redirect("/election");
  }
);
app.post("/admin", async (request, response) => {
  const Pwd = await bcrypt.hash(request.body.password, saltRounds);
  try {
    const admin = await AdminCreate.create({
      firstName: request.body.firstName,
      lastName: request.body.lastName,
      email: request.body.email,
      password: Pwd,
    
    });
    request.login(admin, (err) => {
      if (err) {
        return response.redirect("/");
      } else {
        return response.redirect("/election");
      }
    });
  } catch (error){
    request.flash("error", error.message);
    return response.redirect("/signup");
  }
});
app.get(
  "/election/createNew",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    response.render("NewElection", {
      title: "New Election",
      csrfToken: request.csrfToken(),
    });
  }
);
app.post(
  "/election",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    function whiteSpaces(value) {
      return value.indexOf(" ") >= 0;
    }
      if (request.body.elecName.length < 5) {
        request.flash("error", "Election name length should be a minimum of 5");
        return response.redirect("/election/createNew");
      }
      if (request.body.cstmUrl.length < 5) {
        request.flash("error", "URL String length should be a minimum of 5");
        return response.redirect("/election/createNew");
      }
      const strUrl = request.body.cstmUrl
      const isWhiteScape = whiteSpaces(strUrl)
      if(isWhiteScape == true){
        request.flash("error","Don't enter any white spaces");
        console.log("Spaces found");
        return response.redirect("/election/createNew");
      }
      try {
        await election.addElection({
          elecName: request.body.elecName,
          cstmUrl: request.body.cstmUrl,
          adminID: request.user.id,
        });
        return response.redirect("/election");
      } 
      catch (error) {
        console.log(error);
        request.flash("error", "Election URL is already in use");
        return response.redirect("/election/createNew");
      }
  }
);
app.get(
  "/election/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.id);
        if (request.user.id !== thiselection.adminID){
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Ended) {
          return response.redirect(`/election/${thiselection.id}/results`);
        }
        const numberOfQuestions = await question.getNumberOfQuestions(
          request.params.id
        );
        const numberOfVoters = await voter.getNumberOfVoters(request.params.id);
        return response.render("ElectionOptions", {
          id: request.params.id,
          title: thiselection.elecName,
          cstmUrl: thiselection.cstmUrl,
          Running: thiselection.Running,
          noQuestions: numberOfQuestions,
          noVoters: numberOfVoters,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/election/:id/questions",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.id);
        if (request.user.id!==thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        const thisquestions = await question.gtQuestns(request.params.id);
        if (!thiselection.Running && !thiselection.Ended) {
          if (request.accepts("html")) {
            return response.render("questions", {
              title: thiselection.elecName,
             electionID: request.params.id,
              thisquestions: thisquestions,
              csrfToken: request.csrfToken(),
            });
          } else {
            return response.json({
              ElectionOptions,
            });
          }
        } else {
          if (thiselection.ended) {
            request.flash("error", "Cannot edit when election has ended");
          } else if (thiselection.running) {
            request.flash("error", "Cannot edit while election is running");
          }
          return response.redirect(`/election/${request.params.id}/`);
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.post(
  "/election/:id/questions/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (request.body.question.length < 5) {
        request.flash("error", "Question length should be atleast 5");
        return response.redirect(
          `/election/${request.params.id}/questions/create`
        );
      }
      try {
        const thiselection = await election.getElection(request.params.id);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Running) {
          request.flash("error", "Can't the question edit while election is running");
          return response.redirect(`/election/${request.params.id}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/election/${request.params.id}/`);
        }
        const thisquestion = await question.addQuestions({
          elecQuestion: request.body.question,
          elecDescription: request.body.description,
          electionID: request.params.id,
        });
        return response.redirect(
          `/election/${request.params.id}/questions/${thisquestion.id}`
        );
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);

app.get(
  "/election/:id/questions/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.id);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (!thiselection.Running) {
          return response.render("NewQuestion", {
            id: request.params.id,
            title:thiselection.elecName,
            csrfToken: request.csrfToken(),
          });
        } else {
          if (thiselection.Ended) {
            request.flash("error", "Cannot edit when election has ended");
            return response.redirect(`/election/${request.params.id}/`);
          }
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/election/${request.params.id}/`);
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/election/:id/questions/:questionID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thisquestion = await question.gtQuestns(request.params.id);
        const thisoptions = await options.gtOptns(request.params.questionID);
        const thiselection = await election.getElection(request.params.id);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/elections");
        }
        if (thiselection.Running) {
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        if (request.accepts("html")) {
          response.render("questionPage", {
            title: thisquestion.elecQuestion,
            description: thisquestion.elecDescription,
            id: request.params.id,
            questionID: request.params.questionID,
            thisoptions,
            csrfToken: request.csrfToken(),
          });
        } else {
          return response.json({
            options,
          });
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.post(
  "/election/:id/questions/:questionID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (!request.body.option) {
        request.flash("error", "Please enter option");
        return response.redirect(
          `/election/${request.params.id}/questions/${request.params.questionID}`
        );
      }
      try {
        const thiselection = await election.getElection(request.params.id);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Running) {
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/election/${request.params.id}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        await options.addOption({
          option: request.body.option,
          questionID: request.params.questionID,
        });
        return response.redirect(
          `/election/${request.params.id}/questions/${request.params.questionID}`
        );
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/election/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/elections");
        }
        if (thiselection.Running) {
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/elections/${request.params.electionID}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/elections/${request.params.electionID}/`);
        }
        const thisquestion = await question.gtQuestn(request.params.questionID);
        return response.render("editquestion", {
          electionID: request.params.electionID,
          questionID: request.params.questionID,
          questionTitle: thisquestion.elecQuestion,
          questionDescription: thisquestion.elecDescription,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.put(
  "/election/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (request.body.question.length < 5) {
        request.flash("error", "Question length should be atleast 5");
        return response.json({
          error: "Question length should be atleast 5",
        });
      }
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (thiselection.Running) {
          return response.json("Cannot edit while election is running");
        }
        if (thiselection.Ended) {
          return response.json("Cannot edit when election has ended");
        }
        if (request.user.id !== thiselection.adminID) {
          return response.json({
            error: "Invalid Election ID",
          });
        }
        const updatedQuestion = await question.updateQuestion({
          elecQuestion: request.body.question,
          elecDescription: request.body.description,
          id: request.params.questionID,
        });
        return response.json(updatedQuestion);
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/elections/:electionID/voters",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thisvoters = await voter.getVoters(request.params.electionID);
        const thiselection = await election.getElection(request.params.electionID);
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/elections/${request.params.electionID}/`);
        }
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/elections");
        }
        if (request.accepts("html")) {
          return response.render("voters", {
            title: election.elecName,
            id: request.params.electionID,
            thisvoters,
            csrfToken: request.csrfToken(),
          });
        } else {
          return response.json({
            thisvoters,
          });
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/election/:electionID/voters/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        response.render("newvoter", {
          title: "Add a voter to election",
          id: request.params.electionID,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.post(
  "/election/:electionID/voters/create",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (!request.body.voterUnqid) {
        request.flash("error", "Please enter voterID");
        return response.redirect(
          `/election/${request.params.electionID}/voters/create`
        );
      }
      if (!request.body.voterUnqPswd) {
        request.flash("error", "Please enter password");
        return response.redirect(
          `/election/${request.params.electionID}/voters/create`
        );
      }
      if (request.body.voterUnqPswd.length < 8) {
        request.flash("error", "Password length should be atleast 8");
        return response.redirect(
          `/election/${request.params.electionID}/voters/create`
        );
      }
      const hashedPwd = await bcrypt.hash(request.body.voterUnqPswd, saltRounds);
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        await voter.createVoter({
          voterUnqid: request.body.voterUnqid,
          voterUnqPswd: hashedPwd,
          electionID: request.params.electionID,
        });
        return response.redirect(
          `/election/${request.params.electionID}/voters`
        );
      } catch (error) {
        request.flash("error", "Voter ID already in use");
        return response.redirect(
          `/election/${request.params.electionID}/voters/create`
        );
      }
    }
);
app.get(
  "/election/:id/voters",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    const votersCount = await voter.countOFVoters(request.params.id);
    const thisvoters = await voter.getVoters(request.params.id);
    const thisElection = await election.getElectionWithId(request.params.id);
    const thisElectionName = thisElection.eleName;
    return response.render("voters", {
      votersCount,
      thisvoters,
      csrfToken: request.csrfToken(),
      id: request.params.id,
      thisElectionName,
    });
  }
);
app.get(
  "/election/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        // if (request.user.id !== thiselection.adminID) {
        //   request.flash("error", "Invalid election ID");
        //   return response.redirect("/election");
        // }
        if (thiselection.Running) {
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        console.log(request.params.electionID);
        const thisquestion = await question.gtQuestn(request.params.questionID);
        return response.render("editquestion", {
          electionID: request.params.electionID,
          questionID: request.params.questionID,
          questionTitle: thisquestion.elecQuestion,
          questionDescription: thisquestion.elecDescription,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.put(
  "/election/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (request.body.question.length < 5) {
        request.flash("error", "Question length should be atleast 5");
        return response.json({
          error: "Question length should be atleast 5",
        });
      }
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (thiselection.Running) {
          return response.json("Cannot edit while election is running");
        }
        if (thiselection.Ended) {
          return response.json("Cannot edit when election has ended");
        }
        if (request.user.id !== thiselection.adminID) {
          return response.json({
            error: "Invalid Election ID",
          });
        }
        const updatedQuestion = await question.updateQuestion({
          elecQuestion: request.body.question,
          elecDescription: request.body.description,
          id: request.params.questionID,
        });
        return response.json(updatedQuestion);
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
      
    }
);
app.delete(
  "/election/:electionID/questions/:questionID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (thiselection.Running) {
          return response.json("Cannot edit while election is running");
        }
        if (thiselection.Ended) {
          return response.json("Cannot edit when election has ended");
        }
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        const nofQues = await question.getNumberOfQuestions(
          request.params.electionID
        );
        if (nofQues > 1) {
          const res = await question.deleteQuestion(request.params.questionID);
          return response.json({ success: res === 1 });
        } else {
          return response.json({ success: false });
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
      
    }
);
app.delete(
  "/election/:electionID/questions/:questionID/options/:optionID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/elections");
        }
        if (thiselection.Running) {
          return response.json("Cannot edit while election is running");
        }
        if (thiselection.Ended) {
          return response.json("Cannot edit when election has ended");
        }
        const res = await options.deleteOption(request.params.optionID);
        return response.json({ success: res === 1 });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/election/:electionID/questions/:questionID/options/:optionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/elections");
        }
        if (thiselection.Running) {
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/elections/${request.params.id}/`);
        }
        const option = await options.gtOptn(request.params.optionID);
        return response.render("editoption", {
          option: option.option,
          csrfToken: request.csrfToken(),
          electionID: request.params.electionID,
          questionID: request.params.questionID,
          optionID: request.params.optionID,
          id :request.params.id
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);

app.put(
  "/election/:electionID/questions/:questionID/options/:optionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (!request.body.option) {
        request.flash("error", "Please enter option");
        return response.json({
          error: "Please enter option",
        });
      }
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/elections");
        }
        if (thiselection.Running) {
          return response.json("Cannot edit while election is running");
        }
        if (thiselection.Ended) {
          return response.json("Cannot edit when election has ended");
        }
        const updatedOption = await options.updateOption({
          id: request.params.optionID,
          option: request.body.option,
        });
        return response.json(updatedOption);
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get(
  "/election/:electionID/preview",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        const voters_count = await voter.getNumberOfVoters(
          request.params.electionID
        );
        const thisquestions = await question.gtQuestns(
          request.params.electionID
        );
        let thisoptions = [];
        for (let vquestion in thisquestions) {
          const question_options = await options.gtOptns(
            thisquestions[vquestion].id
          );
          if (question_options.length < 2) {
            request.flash(
              "error",
              "There should be atleast two options in each question"
            );
            request.flash(
              "error",
              "Please add atleast two options to the question below"
            );
            return response.redirect(
              `/election/${request.params.electionID}/questions/${thisquestions[vquestion].id}`
            );
          }
          thisoptions.push(question_options);
        }
        if (thisquestions.length < 1) {
          request.flash(
            "error",
            "Please add atleast one question in the ballot"
          );
          return response.redirect(
            `/election/${request.params.electionID}/questions`
          );
        }
        if (voters_count < 1) {
          request.flash(
            "error",
            "Please add atleast one voter to the election"
          );
          return response.redirect(
            `/election/${request.params.electionID}/voters`
          );
        }
        return response.render("votepreview", {
          title: thiselection.elecName,
          electionID: request.params.electionID,
          thisquestions,
          thisoptions,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.put(
  "/election/:electionID/launch",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          return response.json({
            error: "Invalid Election ID",
          });
        }
        if (thiselection.Ended) {
          return response.json("Cannot launch when election has ended");
        }
        const launchedElection = await election.launchElection(
          request.params.electionID
        );
        return response.json(launchedElection);
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.put(
  "/election/:electionID/end",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          return response.json({
            error: "Invalid Election ID",
          });
        }
        if (!thiselection.Running) {
          return response.json("Cannot end the election before election being launched yet");
        }
        const endElection = await election.endElection(
          request.params.electionID
        );
        return response.json(endElection);
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
app.get("/e/:cstmUrl/voter", async (request, response) => {
  
  try {
    if (request.user) {
      return response.redirect(`/e/${request.params.cstmUrl}`);
    }
    const thiselection = await election.getElectionURL(request.params.cstmUrl);
    return response.render("voterlogin", {
      title: "Login in as Voter",
      cstmUrl: request.params.cstmUrl,
      electionID: thiselection.id,
      csrfToken: request.csrfToken(),
    });
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});
app.post(
  "/e/:cstmUrl/voter",
  passport.authenticate("voter", {
    failureFlash: true,
    failureRedirect: "back",
  }),
  async (request, response) => {
    return response.redirect(`/e/${request.params.cstmUrl}`);
  }
);
app.get("/e/:cstmUrl/", async (request, response) => {
  if (!request.user) {
    request.flash("error", "Please login before trying to Vote");
    return response.redirect(`/e/${request.params.cstmUrl}/voter`);
  }
  if (request.user.didVote) {
    request.flash("error", "You have voted successfully");
    return response.redirect(`/e/${request.params.cstmUrl}/results`);
  }
  try {
    const thiselection = await election.getElectionURL(request.params.cstmUrl);
    if (thiselection.Ended) {
      return response.redirect(`/e/${thiselection.cstmUrl}/results`);
    }
    if (request.user.position === "voter") {
      if (thiselection.Running) {
        const thisquestions = await question.gtQuestns(thiselection.id);
        let thisoptions = [];
        for (let vquestion in thisquestions) {
          thisoptions.push(await options.gtOptns(thisquestions[vquestion].id));
        }
        return response.render("vote", {
          title: thiselection.elecName,
          electionID: thiselection.id,
          thisquestions,
          thisoptions,
          cstmUrl: request.params.cstmUrl,
          csrfToken: request.csrfToken(),
        });
      } else {
        return response.render("404");
      }
    } else if (request.user.position === "admin") {
      request.flash("error", "You cannot vote as Admin");
      request.flash("error", "Please signout as Admin before trying to vote");
      return response.redirect(`/elections/${election.id}`);
    }
  } catch (error) {
    console.log(error);
    return response.status(422).json(error); //test
  }
});
app.post("/e/:cstmUrl", async (request, response) => {
  if (!request.user) {
    request.flash("error", "Please login before trying to Vote");
    return response.redirect(`/e/${request.params.cstmUrl}/voter`);
  }
  if (request.user.didVote) {
    request.flash("error", "You have voted successfully");
    return response.redirect(`/e/${request.params.cstmUrl}/results`);
  }
  try {
    let thiselection = await election.getElectionURL(request.params.cstmUrl);
    if (thiselection.Ended) {
      request.flash("error", "Cannot vote when election has ended");
      return response.redirect(`/election/${request.params.id}/results`);
    }
    let thisquestions = await question.gtQuestns(thiselection.id);
    for (let vquestion of thisquestions) {
      console.log(vquestion)
      let qid = `q-${vquestion.id}`;
      let selectedOption = request.body[qid];
      let addedAnswer = await Answers.addAnswer({
        voterID: request.user.id,
        electionID: thiselection.id,
        questionID: vquestion.id,
        OptionBool: selectedOption,
      });
    }
    await voter.markAsVoted(request.user.id);
    return response.redirect(`/e/${request.params.cstmUrl}/results`);
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});
app.get("/e/:cstmUrl/results", async (request, response) => {
  try {
    const thiselection = await election.getElectionwithUrl(
      request.params.cstmUrl
    );
    if (!thiselection.Running && !thiselection.Ended) {
      return response.status(404).render("error");
    }
    if (!thiselection.Ended && request.user.position === "voter") {
      return response.render("Thankyou");
    }
    const thisquestions = await question.gtQuestns(thiselection.id);
    const thisanswers = await Answers.gtanswers(thiselection.id);
    let thisoptions = [];
    let optionLabels = [];
    let optionsCount = [];
    let winners = [];
    for (let questions in thisquestions) {
      let vals = await options.gtOptns(thisquestions[questions].id);
      thisoptions.push(vals);
      let vals_count = [];
      let vals_labels = [];
      let electionid=thiselection.id
      for (let opt in vals) {
        vals_labels.push(vals[opt].option);
        vals_count.push(
          await Answers.gtOptnCount({
            electionID: electionid,
            OptionBool: vals[opt].id,
            questionID: thisquestions[questions].id,
          })
        );
      }
      winners.push(Math.max.apply(Math, vals_count));
      optionLabels.push(vals_labels);
      optionsCount.push(vals_count);
    }
    const noofVoted = await voter.countVoted(thiselection.id);
    const nNotVoted = await voter.Pending(thiselection.id);
    const totalVoters = noofVoted + nNotVoted;
    return response.render("thank-you", {
      elecName: thiselection.elecName,
      thisanswers,
      thisquestions,
      thisoptions,
      optionsCount,
      optionLabels,
      winners,
      noofVoted,
      nNotVoted,
      totalVoters,
    });
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});

app.get("/election/:id/results", async (request, response) => {
  try {
    console.log(request.params.id+"kajjfljasdlfk")
    const thiselection = await election.findOne({where: {
      id:request.params.id
    }})
    if (!thiselection.Running && !thiselection.Ended) {
      console.log("error here 1")
      return response.status(404).render("error");
    }
    if (!thiselection.Ended && request.user.position === "voter") {
      console.log("error here 2")
      return response.render("Thankyou");
    }
    const thisquestions = await question.gtQuestns(thiselection.id);
    const thisanswers = await Answers.gtanswers(thiselection.id);
    let thisoptions = [];
    let optionLabels = [];
    let optionsCount = [];
    let winners = [];
    for (let questions in thisquestions) {
      let vals = await options.gtOptns(thisquestions[questions].id);
      thisoptions.push(vals);
      let vals_count = [];
      let vals_labels = [];
      let electionid=thiselection.id
      for (let opt in vals) {
        vals_labels.push(vals[opt].option);
        vals_count.push(
          await Answers.gtOptnCount({
            electionID: electionid,
            OptionBool: vals[opt].id,
            questionID: thisquestions[questions].id,
          })
        );
      }
      winners.push(Math.max.apply(Math, vals_count));
      optionLabels.push(vals_labels);
      optionsCount.push(vals_count);
    }
    const noofVoted = await voter.countVoted(thiselection.id);
    const nNotVoted = await voter.Pending(thiselection.id);
    const totalVoters = noofVoted + nNotVoted;
    return response.render("thank-you", {
      elecName: thiselection.elecName,
      thisanswers,
      thisquestions,
      thisoptions,
      optionsCount,
      optionLabels,
      winners,
      noofVoted,
      nNotVoted,
      totalVoters,
    });
  } catch (error) {
    console.log(error);
    console.log("error here 3")

    return response.status(422).json(error);
  }
});

app.get(
  "/election/:electionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        const thiselection = await election.getElection(request.params.electionID);
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        if (thiselection.Running) {
          request.flash("error", "Cannot edit while election is running");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        if (thiselection.Ended) {
          request.flash("error", "Cannot edit when election has ended");
          return response.redirect(`/election/${request.params.electionID}/`);
        }
        return response.render("editelection", {
          electionID: request.params.electionID,
          csrfToken: request.csrfToken(),
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);

app.put(
  "/election/:electionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      if (request.body.elecName.length < 5) {
        request.flash("error", "Election name length should be atleast 5");
        return response.redirect(
          `/election/${request.params.electionID}/edit`
        );
      }
      if (request.body.cstmUrl.length < 3) {
        request.flash("error", "URL String length should be atleast 3 characters");
        return response.redirect(
          `/election/${request.params.electionID}/edit`
        );
      }
      try {
        const thiselection = await election.getElectionWithId(request.params.electionID);
        console.log(thiselection)
        if (thiselection.Running) {
          return response.json("Cannot edit while election is running");
        }
        if (thiselection.Ended) {
          return response.json("Cannot edit when election has ended");
        }
        if (request.user.id !== thiselection.adminID) {
          return response.json({
            error: "Invalid Election ID",
          });
        }
        return response.json(updatedElection);
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    
      return response.redirect("/");
    }
  
);

app.delete(
  "/election/:electionID",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
      try {
        console.log("testing\n\n\n\n")
        const thiselection = await election.getElection(request.params.electionID);
        if (thiselection.Running) {
          return response.json("Cannot delete while election is running");
        }
        if (request.user.id !== thiselection.adminID) {
          request.flash("error", "Invalid election ID");
          return response.redirect("/election");
        }
        const res = await election.deleteElection(request.params.electionID);
        return response.json({ success: res === 1 });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
);
module.exports = app;