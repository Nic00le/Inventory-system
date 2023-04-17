import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'

const routes = [
  {
    path: '/',
    name: 'home',
    component: HomeView
  },
  {
    path: '/login',
    name: 'LoginView',
    component: () => import(/* webpackChunkName: "about" */ '../views/LoginView.vue')
  },
  {
    path: '/:type',
    name: 'TypeView',
    component: () => import(/* webpackChunkName: "about" */ '../views/TypeView.vue')
  },
  {
    path: '/:type/detail',
    name: 'FormView',
    component: () => import(/* webpackChunkName: "about" */ '../views/DetailView.vue')
  },
  {
    path: '/:type/detail/:id',
    name: 'DetailView',
    component: () => import(/* webpackChunkName: "about" */ '../views/DetailView.vue')
  },
  {
    path: '/search/:input',
    name: 'SearchView',
    component: () => import(/* webpackChunkName: "about" */ '../views/SearchView.vue')
  },
  {
    path: '/users',
    name: 'UsersView',
    component: () => import(/* webpackChunkName: "about" */ '../views/UsersView.vue'),
    meta: {adminAuth: true }
  },
  {
    path: '/user/detail',
    name: 'UserCreateView',
    component: () => import(/* webpackChunkName: "about" */ '../views/UserDetailView.vue'),
    meta: {adminAuth: true }
  },
  {
    path: '/user/detail/:id',
    name: 'UserUpdateView',
    component: () => import(/* webpackChunkName: "about" */ '../views/UserDetailView.vue'),
    meta: {adminAuth: true }
  },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

router.beforeEach((to, from, next) => {
  let role = localStorage.getItem('type');
  if (to.path === '/login' || to.path === '/') {
    next();
  } else {
    let token = localStorage.getItem('token');
 
    if (!token) {
      alert("Please login first.")
      next('/login');
    } else {
      next();
    }
  }

  if (to.meta.adminAuth) {
    if (role === "admin") {
      return next();
    } else {
      alert("You don't have the access right.");
      router.push({path: '/'});
    }
  }

});

export default router
