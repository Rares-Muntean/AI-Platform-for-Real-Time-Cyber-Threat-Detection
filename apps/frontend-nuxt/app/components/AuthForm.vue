<script lang="ts" setup>
import { reactive, ref, watch } from "vue";
import type { User } from "~/types/types";

const props = defineProps<{
    isLogin: boolean;
}>();

const { createAccount, loginUser } = useUsers();

const form: User = reactive({
    firstName: "",
    lastName: "",
    email: "",
    password: "",
});

const validationError = ref("");

const getPasswordRequirements = () => {
    const missing = [];
    if (form.password.length < 8) missing.push("8+ characters");
    if (!/[A-Z]/.test(form.password)) missing.push("uppercase");
    if (!/\d/.test(form.password)) missing.push("number");
    if (!/[!@#$%&?]/.test(form.password)) missing.push("special character");
    return missing;
};

const handleSubmit = async () => {
    validationError.value = "";

    if (props.isLogin) {
        try {
            const response = await loginUser({
                email: form.email,
                password: form.password,
            });
            // Handle token storage (cookie)
            console.log("Login Token:", response.token);

            await navigateTo("/dashboard");
        } catch (e) {
            console.error("Login Failed: ", e);
            validationError.value = "Invalid email or password.";
        }
    } else {
        const missing = getPasswordRequirements();
        if (missing.length > 0) {
            validationError.value =
                "Password needs: " + missing.join(", ") + ".";
            return;
        }

        try {
            await createAccount({
                firstName: form.firstName,
                lastName: form.lastName,
                email: form.email,
                password: form.password,
            });

            const loginResponse = await loginUser({
                email: form.email,
                password: form.password,
            });
            console.log("Auto-login Token:", loginResponse.token);

            await navigateTo("/dashboard");
        } catch (e: any) {
            console.error("Signup Failed: ", e);
            validationError.value = "Server error. Please try again.";
        }
    }
};

watch(
    () => form.password,
    () => {
        if (props.isLogin) return;

        if (
            validationError.value &&
            !validationError.value.includes("Server error")
        ) {
            const missing = getPasswordRequirements();
            if (missing.length === 0) {
                validationError.value = "";
            } else {
                validationError.value =
                    "Password needs: " + missing.join(", ") + ".";
            }
        }
    },
);
</script>

<template>
    <section class="section">
        <RadialGradient
            :size="1500"
            :position-x="-50"
            :position-y="40"
            :bottom="0"
            :left="0"
            :opacity="1"
        />
        <RadialGradient
            :size="800"
            :position-x="65"
            :position-y="45"
            :bottom="0"
            :right="0"
        />

        <div class="signup-container">
            <div class="logo-wrapper">
                <div class="logo-container">
                    <img class="logo-icon" src="/images/logo-icon.png" />
                    <p class="icon-text">VELOX</p>
                </div>
                <Separator />
            </div>

            <div class="heading-wrapper">
                <h1 class="title">
                    {{
                        isLogin ? "Log in to your account" : "Create an account"
                    }}
                </h1>
                <p class="description">
                    {{
                        isLogin
                            ? "Welcome back! Please enter your details."
                            : "Start securing your devices with ease."
                    }}
                </p>
            </div>

            <form @submit.prevent="handleSubmit">
                <div class="input-wrapper">
                    <div v-if="!isLogin" class="full-name">
                        <input
                            v-model="form.firstName"
                            type="text"
                            id="first-name"
                            placeholder="First Name"
                            required
                        />
                        <input
                            v-model="form.lastName"
                            type="text"
                            id="last-name"
                            placeholder="Last Name"
                            required
                        />
                    </div>

                    <input
                        v-model="form.email"
                        type="email"
                        id="email"
                        placeholder="Email"
                        required
                    />

                    <div class="password-input">
                        <input
                            v-model="form.password"
                            type="password"
                            id="password"
                            placeholder="Password"
                            required
                        />
                        <p v-if="validationError" class="validation-msg">
                            {{ validationError }}
                        </p>
                    </div>
                </div>

                <button type="submit" class="btn-primary stretched btn-signup">
                    {{ isLogin ? "Log in" : "Create account" }}
                </button>
            </form>

            <p class="login-redirect">
                <template v-if="isLogin">
                    Don't have an account?
                    <NuxtLink to="/signup">Sign up</NuxtLink>
                </template>
                <template v-else>
                    Already have an account?
                    <NuxtLink to="/login">Log in</NuxtLink>
                </template>
            </p>
        </div>
    </section>
</template>

<style lang="scss" scoped src="~/assets/scss/general/authForm.scss"></style>
