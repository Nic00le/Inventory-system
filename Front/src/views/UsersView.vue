<template>
  <div>
    <nav aria-label="breadcrumb">
      <ol class="breadcrumb">
        <li class="breadcrumb-item"><a href="/">Home</a></li>
        <li class="breadcrumb-item active" aria-current="page">Users</li>
        <button type="button" class="btn btn-primary position-absolute top-20 end-0" @click="add">Add</button>
      </ol>
    </nav>
  </div>
  <div class="row row-cols-1 row-cols-md-4 g-4">
    <UserCard v-for="u in users" :key="u._id" :id="u._id" :name="u.name" :email="u.email" />
  </div>
  <nav aria-label="Page navigation example">
    <ul class="pagination">
      <li class="page-item">
        <a a v-if="currentPage > 1" class="page-link" @click="currentPage--">
          <span aria-hidden="true">&laquo;</span>
        </a>
      </li>
      <li class="page-item"><a v-if="currentPage > 2" class="page-link" @click="currentPage = currentPage - 2">{{
          currentPage - 2
      }}</a></li>
      <li class="page-item"><a v-if="currentPage > 1" class="page-link" @click="currentPage--">{{ currentPage - 1
      }}</a></li>
      <li class="page-item"><a class="page-link active">{{ currentPage }}</a></li>
      <li class="page-item"><a v-if="currentPage < pages.length" class="page-link" @click="currentPage++">{{
          currentPage + 1
      }}</a></li>
      <li class="page-item"><a v-if="currentPage < pages.length - 1" class="page-link"
          @click="currentPage = currentPage + 2">{{ currentPage + 2 }}</a></li>
      <li class="page-item">
        <a v-if="currentPage < pages.length" class="page-link" @click="currentPage++">
          <span aria-hidden="true">&raquo;</span>
        </a>
      </li>
    </ul>
  </nav>
</template>


<script>

import UserCard from "@/components/UserCard.vue";
import { ref, onMounted, computed, watch } from "vue";

export default {
  name: 'UserView',
  components: {
    UserCard
  },
  setup() {
    const users = ref([]);
    const lastPage = ref(0);
    const perPage = ref(8);
    const currentPage = ref(1);

    const add = async function () {
      location.assign("/user/detail")
    }


    const fetchPage = async function (page) {

      var response = await fetch("/api/users/display?perPage=" + perPage.value + "&page=" + page);

      if (response.ok) {
        var data = await response.json();
        users.value = data.records;
        lastPage.value = data.pages;
      } else {
        alert(response.statusText);
      }
    };

    const pages = computed(() => {
      var pages = [];

      for (var i = 1; i <= lastPage.value; i++) {
        pages.push(i)
      }

      return pages;
    })

    onMounted(function () {
      fetchPage(1);
    });

    watch(currentPage, () => {
      fetchPage(currentPage.value)
    });

    return {
      users,
      pages,
      fetchPage,
      currentPage,
      add
    };

  }
}

</script>


    