package com.vaadin.demo.ui.views;

import com.vaadin.event.ShortcutAction;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;

public class LoginView extends VerticalLayout {


    public LoginView(LoginCallback callback) {
        addStyleName("login-view");
        setMargin(false);

        setSizeFull();
        setDefaultComponentAlignment(Alignment.MIDDLE_CENTER);

        Label title = new Label("Patient Portal");
        title.addStyleName(ValoTheme.LABEL_H1);

        TextField usernameField = new TextField("Username");
        PasswordField passwordField = new PasswordField("Password");
        usernameField.setWidth("100%");
        passwordField.setWidth("100%");

        Label errorLabel = new Label();

        Button loginButton = new NativeButton("Login");
        loginButton.setClickShortcut(ShortcutAction.KeyCode.ENTER);
        loginButton.addStyleName(ValoTheme.BUTTON_PRIMARY);
        loginButton.addClickListener(click -> {
            String password = passwordField.getValue();
            passwordField.clear();

            if(!callback.login(usernameField.getValue(), password)){
                errorLabel.setValue("Login failed.");
            }
        });



        VerticalLayout loginBox = new VerticalLayout(title, usernameField, passwordField, loginButton, errorLabel);
        loginBox.addStyleName("login-box");
        loginBox.setSizeUndefined();
        addComponent(loginBox);
    }


    @FunctionalInterface
    public interface LoginCallback {
        boolean login(String username, String password);
    }
}
