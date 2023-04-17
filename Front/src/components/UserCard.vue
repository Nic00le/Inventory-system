<template>
    <div class="col">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">{{ name }}</h5>
                <p>{{ email }}</p>
                <a :href="path">update</a>
            </div>
        </div>
    </div>
</template>

<script>

export default {
    name: "UserCard",
    props: {
        id: String,
        name: String,
        email: String,
    },
    setup(props) {
        const path = "/user/detail/" + props.id

        return {
            path
        }
    }
}
</script>
