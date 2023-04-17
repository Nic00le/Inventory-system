<template>
  <div class="col">
    <!-- <RouterLink :to="path"> -->
    <div class="card">
      <img :src="src" class="card-img-top" alt="Photo is gone">
      <div class="card-body">
        <a :href="path">
          <h5 class="card-title">{{ title }}</h5>
          <p>{{ descriptions }}</p>
        </a>
        <div v-if="type == 'books' || type == 'games'">
          <p v-if="borrowerId && borrowerId!=userId">Borrowed by {{ borrowerName }}</p>
          <button v-if="!borrowerId" type="button" class="btn btn-primary" @click="borrow">Borrow</button>
          <button v-if="borrowerId == userId" type="button" class="btn btn-outline-primary"
            @click="returnItem">Return</button>
        </div>
        <div v-if="type == 'gifts' || type == 'materials'">
          <p v-if="quantity">Availability: {{ quantity-comsumes }}</p>
          <button v-if="(quantity-comsumes)>0" type="button" class="btn btn-primary" @click="comsume">Comsume</button>
        </div>
      </div>
    </div>
    <!-- </RouterLink> -->
  </div>
</template>

<style>
a {
  color: #202223;
  text-decoration: none;
}
</style>

<script>
import { ref } from "vue";

export default {
  name: "TheCards",
  props: {
    id: String,
    type: String,
    src: String,
    title: String,
    descriptions: String,
    comsumes: Int32Array,
    quantity: Int32Array,
    borrowerId: String,
    borrowerName: String
  },
  setup(props) {
    const path = "/" + props.type + "/detail/" + props.id;
    const userId = localStorage.getItem("userId");

    const borrow = async function () {
      let token = ref(localStorage.getItem('token'));
      let path = "/api/user/borrow/" + props.id;

      var response = await fetch(path, {
        method: "post",
        headers: {
          // 'Content-Type': 'application/x-www-form-urlencoded',
          "x-access-token": token.value
        }
      });
      if (response.ok) {
        alert("Borrow success.")
        location.reload();
      } else {
        alert(response.statusText);
      }

    }

    const comsume = async function () {
      let token = ref(localStorage.getItem('token'));
      let path = "/api/user/comsume/" + props.id;

      var response = await fetch(path, {
        method: "post",
        headers: {
          // 'Content-Type': 'application/x-www-form-urlencoded',
          "x-access-token": token.value
        }
      });
      if (response.ok) {
        alert("Success.")
        location.reload();
      } else {
        alert(response.statusText);
      }

    }

    const returnItem = async function () {
      let token = ref(localStorage.getItem('token'));
      let path = "/api/user/return/" + props.id;

      var response = await fetch(path, {
        method: "post",
        headers: {
          // 'Content-Type': 'application/x-www-form-urlencoded',
          "x-access-token": token.value
        }
      });
      if (response.ok) {
        alert("Returned")
        location.reload();
      } else {
        alert(response.statusText);
      }

    }

    return {
      path,
      borrow,
      comsume,
      returnItem,
      userId
    }
  }
}
</script>