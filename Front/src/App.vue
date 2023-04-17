<template>
  <nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="/">Inventory</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent"
      aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div v-if="token" class="collapse navbar-collapse" id="navbarSupportedContent">
      <ul class="navbar-nav mr-auto">
        <li class="nav-item active">
          <a class="nav-link" href="/books">Books</a>
        </li>
        <li class="nav-item active">
          <a class="nav-link" href="/games">Games</a>
        </li>
        <li class="nav-item active">
          <a class="nav-link" href="/gifts">Gifts</a>
        </li>
        <li class="nav-item active">
          <a class="nav-link" href="/materials">Materials</a>
        </li>
        <li v-if="type == 'admin'" class="nav-item active">
          <a class="nav-link" href="/users">Users</a>
        </li>
      </ul>
      <form class="d-flex ms-auto order-5" @submit.prevent="search">
        <input class="form-control mr-sm-2" type="search" placeholder="search" aria-label="Search"
          v-model="searchparams">
        <button class="btn btn-outline-success" type="submit">Search</button>
        
        <button class="btn btn-sm btn-outline-danger" type="button" @click="logout">LogOut</button>
      </form>
    </div>
    <button v-if="!token" type="button" class="btn btn-outline-primary position-absolute top-20 end-0" @click="login">Sign in</button>
  </nav>
  <router-view />
</template>

<script>
import { ref } from "vue";
export default {
  setup() {
    let token = localStorage.getItem('token');
    let type = localStorage.getItem('type');

    const searchparams = ref("");

    const search = async function () {
      location.assign("/search/" + searchparams.value)
    }

    const login = async function () {
      location.assign("/login")
    }

    const logout = function () {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      localStorage.removeItem('email');
      location.assign("/")
    }

    return {
      searchparams,
      search,
      login,
      logout,
      token,
      type
    }
  }
}
</script>


<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

nav {
  padding: 30px;
  margin: auto;
}

nav a {
  font-weight: bold;
  color: #2c3e50;
}

nav a.router-link-exact-active {
  color: #42b983;
}
</style>
