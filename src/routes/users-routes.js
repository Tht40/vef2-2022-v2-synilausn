import express from 'express';
import { validationResult } from 'express-validator';
import { catchErrors } from '../lib/catch-errors.js';
import {
  createEvent,
  listEvent,
  listEventByName,
  listEvents, listUsers, updateEvent
} from '../lib/db.js';
import passport, { ensureLoggedIn } from '../lib/login.js';
import { slugify } from '../lib/slugify.js';
import { checkisAdmin, createUser, findByUsername } from '../lib/users.js';
import {
  registrationValidationMiddleware,
  sanitizationMiddleware,
  xssSanitizationMiddleware
} from '../lib/validation.js';

export const usersRouter = express.Router();


async function index(req, res) {
  const events = await listEvents();
  const { user: { username } = {} } = req || {};
  const { user: { admin } = {} } = req || {};
  /* const { user: { id } = {} } = req || {}; */

  return res.render('users', {
    username,
    events,
    errors: [],
    data: {},
    title: 'Viðburðir — umsjón',
    admin: checkisAdmin(admin),
    /* isOwner: checkisOwner(id), */
  });
}

async function allUsers(req, res) {
  const users = await listUsers();
  const { user: { username, name, id } = {} } = req || {};
  const { user: { admin } = {} } = req || {};

  return res.render('allusers', {
    username,
    users,
    name,
    id,
    errors: [],
    data: {},
    title: 'Notendur -- umsjón',
    admin: checkisAdmin(admin),

  });
}

function login(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/users');
  }

  let message = '';

  // Athugum hvort einhver skilaboð séu til í session, ef svo er birtum þau
  // og hreinsum skilaboð
  if (req.session.messages && req.session.messages.length > 0) {
    message = req.session.messages.join(', ');
    req.session.messages = [];
  }

  return res.render('login', { message, title: 'Innskráning' });
}


async function create(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/users');
  }

  let message = '';

  if (req.session.messages && req.session.messages.length > 0) {
    message = req.session.messages.join(', ');
    req.session.messages = [];

  }
  return res.render('register', { message, title: 'Nýskráning' });
}


async function validationCheck(req, res, next) {
  const { name, description } = req.body;

  const events = await listEvents();
  const { user: { username } = {} } = req;
  const { user: { admin } = {} } = req || {};


  const data = {
    name,
    description,
  };

  const validation = validationResult(req);

  const customValidations = [];

  const eventNameExists = await listEventByName(name);

  if (eventNameExists !== null) {
    customValidations.push({
      param: 'name',
      msg: 'Viðburður með þessu nafni er til',
    });
  }

  if (!validation.isEmpty() || customValidations.length > 0) {
    return res.render('users', {
      events,
      username,
      title: 'Viðburðir — umsjón',
      data,
      errors: validation.errors.concat(customValidations),
      admin: checkisAdmin(admin),
    });
  }

  return next();
}

async function validationCheckUpdate(req, res, next) {
  const { name, description } = req.body;
  const { slug } = req.params;
  const { user: { username } = {} } = req;
  const { user: { admin } = {} } = req || {};


  const event = await listEvent(slug);

  const data = {
    name,
    description,
  };

  const validation = validationResult(req);

  const customValidations = [];

  const eventNameExists = await listEventByName(name);

  if (eventNameExists !== null && eventNameExists.id !== event.id) {
    customValidations.push({
      param: 'name',
      msg: 'Viðburður með þessu nafni er til',
    });
  }

  if (!validation.isEmpty() || customValidations.length > 0) {
    return res.render('users-event', {
      username,
      event,
      title: 'Viðburðir — umsjón',
      data,
      errors: validation.errors.concat(customValidations),
      admin: checkisAdmin(admin),
    });
  }

  return next();
}

async function registerRoute(req, res) {
  const { name, description } = req.body;
  const slug = slugify(name);

  const created = await createEvent({ name, slug, description });

  if (created) {
    return res.redirect('/users');
  }

  return res.render('error');
}

async function updateRoute(req, res) {
  const { name, description } = req.body;
  const { slug } = req.params;

  const event = await listEvent(slug);

  const newSlug = slugify(name);

  const updated = await updateEvent(event.id, {
    name,
    slug: newSlug,
    description,
  });

  if (updated) {
    return res.redirect('/users');
  }

  return res.render('error');
}

async function eventRoute(req, res, next) {
  const { slug } = req.params;
  const { user: { username } = {} } = req;

  const event = await listEvent(slug);

  if (!event) {
    return next();
  }

  return res.render('users-event', {
    username,
    title: `${event.name} — Viðburðir — umsjón`,
    event,
    errors: [],
    data: { name: event.name, description: event.description },
  });
}

usersRouter.get('/', ensureLoggedIn, catchErrors(index));
usersRouter.get('/allusers', catchErrors(allUsers));
usersRouter.post(
  '/',
  ensureLoggedIn,
  registrationValidationMiddleware('description'),
  xssSanitizationMiddleware('description'),
  catchErrors(validationCheck),
  sanitizationMiddleware('description'),
  catchErrors(registerRoute)
);

usersRouter.get('/login', login);
usersRouter.post(
  '/login',

  // Þetta notar strat að ofan til að skrá notanda inn
  passport.authenticate('local', {
    failureMessage: 'Notandanafn eða lykilorð vitlaust.',
    failureRedirect: '/users/login',
  }),

  // Ef við komumst hingað var notandi skráður inn, senda á /admin
  (req, res) => {
    res.redirect('/users');
  }
);

// býr til nýjann account
usersRouter.get('/register', create);
usersRouter.post('/register', (req, res) => {

  const { name, username, password, password2 } = req.body;
  if (JSON.stringify(findByUsername(username)) === '{}' && password === password2) {

    createUser(name, username, password);
    return res.redirect('/users');
  }

  const message = 'Notandi er nú þegar til eða lykilorðin eru ekki eins';
  return res.render('register', {
    title: 'Nýskráning',
    message
  });


});



usersRouter.get('/logout', (req, res) => {
  // logout hendir session cookie og session
  req.logout();
  res.redirect('/');
});

// Verður að vera seinast svo það taki ekki yfir önnur route
usersRouter.get('/:slug', ensureLoggedIn, catchErrors(eventRoute));
usersRouter.post(
  '/:slug',
  ensureLoggedIn,
  registrationValidationMiddleware('description'),
  xssSanitizationMiddleware('description'),
  catchErrors(validationCheckUpdate),
  sanitizationMiddleware('description'),
  catchErrors(updateRoute)
);
