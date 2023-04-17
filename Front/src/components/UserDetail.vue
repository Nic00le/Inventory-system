<template>
    <div class="container">
        <form @submit.prevent="createUser()">
            <div class="row">
                <div class="form-group col-md-6">
                    <label for="exampleInputEmail1" class="form-label">Email address</label>
                    <input type="email" class="form-control" v-model="user.email" aria-describedby="email">
                    <div id="emailHelp" class="form-text">We'll never share your email with anyone else.</div>
                </div>
                <div class="form-group col-md-6">
                    <label for="exampleInputEmail1" class="form-label">Full Name</label>
                    <input type="text" class="form-control" v-model="user.name" aria-describedby="full name">
                </div>
            </div>
            <div class="row">
                <div class="form-group col-md-4">
                    <label for="exampleInputPassword1" class="form-label">Password</label>
                    <input type="password" class="form-control" v-model="user.password">
                </div>
                <div class="form-group col-md-4">
                    <label for="exampleInputPassword1" class="form-label">Type</label>
                    <select class="form-control" v-model="user.type">
                        <option selected>Open this select menu</option>
                        <option value="admin">Admin</option>
                        <option value="user">User</option>
                    </select>
                </div>
                <div class="form-group col-md-4">
                    <label for="exampleInputPassword1" class="form-label">Phone</label>
                    <input type="text" class="form-control" v-model="user.phone">
                </div>
            </div>
            <button v-if="!$route.params.id" type="submit" class="btn btn-primary">Save</button>
        </form>
        <div v-if="$route.params.id">
            <button @click.prevent="updateUser" class="btn btn-primary">Update</button>
            <button @click.prevent="deleteUser" class="btn btn-danger">Delete</button>
        </div>
    </div>
</template>

<script>
import { ref, onMounted } from "vue";


export default {
    name: 'UserDetail',
    props: {
        id: String,
        newRecord: Boolean
    },
    setup(props) {
        const user = ref({});

        onMounted(async () => {
            if (props.id) {
                var response = await fetch("/api/user/detail/" + props.id)
                console.log(props.id)
                console.log(response)

                if (response.ok) {
                    user.value = await response.json();
                }
            }
        });

        const createUser = async function () {

            var response = await fetch("/api/user/create", {
                method: "post",
                headers: {
                    // 'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Type': 'application/json'
                },

                // body: new URLSearchParams(new FormData(event.target))
                body: JSON.stringify(user.value)
            });
            console.log(user.value)
            if (response.ok) {

                var text = await response.text();
                alert(text);
                location.assign("/users")
                // location.assign("/bookings")
            } else {
                alert(response.statusText)
            }
        }

        const updateUser = async function () {
            delete user.value._id;

            var response = await fetch("/api/user/update/" + props.id, {
                method: "put",
                headers: {
                    // 'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Type': 'application/json'
                },

                // body: new URLSearchParams(new FormData(event.target))
                body: JSON.stringify(user.value)
            });
            console.log(user.value)
            if (response.ok) {

                var text = await response.text();
                alert(text);
                // location.assign("/bookings")
            } else {
                alert(response.statusText)
            }
        }

        const deleteUser = async function () {

            var response = await fetch("/api/user/delete/" + props.id , {
                method: "delete",
                headers: {
                    // 'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Type': 'application/json'
                }

                // body: new URLSearchParams(new FormData(event.target))
                // body: JSON.stringify(records.value)
            });
            if (response.ok) {
                // var text = await response.text();
                alert("User is deleted");
                // location.assign("/bookings")
            } else {
                alert(response.statusText)
            }
        }

        return {
            user,
            createUser,
            updateUser,
            deleteUser
        }
    }
}
</script>