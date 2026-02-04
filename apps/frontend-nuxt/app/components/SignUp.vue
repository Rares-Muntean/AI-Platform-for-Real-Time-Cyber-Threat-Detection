<script lang="ts" setup>
import { reactive } from "vue";

const form = reactive({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
});

const handleSubmit = () => {
    console.log("Form Submitted:", form);
};
</script>

<template>
    <section class="section">
        <div class="logo-wrapper">
            <img />
            <p class="icon-text">VELOX</p>
            <Separator />
        </div>

        <div class="heading-wrapper">
            <h1 class="title">Create an account</h1>
            <p class="description">Start securing your devices with ease.</p>
        </div>

        <form action="" @submit.prevent="handleSubmit">
            <div class="input-wrapper">
                <div class="full-name">
                    <input
                        v-model="form.firstName"
                        type="text"
                        id="first-name"
                        placeholder="First Name"
                    />
                    <input
                        v-model="form.lastName"
                        type="text"
                        id="last-name"
                        placeholder="Last Name"
                    />
                </div>

                <input
                    v-model="form.email"
                    type="text"
                    id="email"
                    placeholder="Email"
                />
                <input
                    v-model="form.password"
                    type="text"
                    id="password"
                    placeholder="Password"
                />
            </div>

            <button type="submit" class="btn-primary stretched">
                Create account
            </button>
        </form>

        <p class="login-redirect">
            Already have an account? <a href="#">Log in</a>
        </p>
    </section>
</template>

<style lang="scss" src="~/assets/scss/scoped/SignUp.scss"></style>
