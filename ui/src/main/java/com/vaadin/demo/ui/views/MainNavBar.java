package com.vaadin.demo.ui.views;

import com.vaadin.demo.ui.views.base.NavBar;
import com.vaadin.icons.VaadinIcons;
import com.vaadin.server.Page;
import com.vaadin.shared.Registration;
import com.vaadin.ui.Alignment;
import com.vaadin.ui.NativeButton;

class MainNavBar extends NavBar {
    private Registration registration;

    MainNavBar() {
        addStyleName("main-nav");
        setSpacing(false);
        setMargin(false);
        addAttachListener(attachEvent -> setupView());
    }

    private void setupView() {
        navButtons.put("patients", new NativeButton("Patients"));
        navButtons.put("analytics", new NativeButton("Analytics"));

        navButtons.forEach((name, button) -> {
            button.addStyleName("link");
            button.addClickListener(click -> getUI().getNavigator().navigateTo(name));
            addComponent(button);
        });

        NativeButton logout = new NativeButton("Logout", click -> {
            Page.getCurrent().reload();
            getSession().close();
        });
        logout.addStyleName("link");
        logout.setIcon(VaadinIcons.SIGN_OUT);

        addComponentsAndExpand(logout);
        logout.setWidth(null);
        setComponentAlignment(logout, Alignment.MIDDLE_RIGHT);
    }



    @Override
    public void attach() {
        super.attach();
        registration = getUI().getNavigator().addViewChangeListener(viewChange -> {
            String viewName = viewChange.getViewName();
            navButtons.forEach((name, button) -> {
                if (name.equals(viewName)) {
                    button.addStyleName("active");
                } else {
                    button.removeStyleName("active");
                }
            });

            return true;
        });
    }

    @Override
    public void detach() {
        super.detach();
        registration.remove();
    }
}
