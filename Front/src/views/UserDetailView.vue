<template> 
<div> 
    <nav aria-label="breadcrumb">
    <ol class="breadcrumb">
      <li class="breadcrumb-item"><a href="/">Home</a></li>
      <li class="breadcrumb-item"><a href="/users">Users</a></li>
      <li class="breadcrumb-item active" aria-current="page">User Detail</li>
    </ol>
  </nav>
    <UserDetail :id="$route.params.id"/>
</div>
</template>

<script>

import UserDetail from "@/components/UserDetail.vue";

export default {
  name: 'UserDetailView',
  components: {
    UserDetail
  }
}

</script>
