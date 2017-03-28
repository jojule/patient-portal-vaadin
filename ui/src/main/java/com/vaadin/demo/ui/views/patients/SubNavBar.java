package com.vaadin.demo.ui.views.patients;

import com.vaadin.demo.ui.views.base.NavBar;
import com.vaadin.icons.VaadinIcons;
import com.vaadin.ui.Alignment;
import com.vaadin.ui.HorizontalLayout;
import com.vaadin.ui.NativeButton;
import io.reactivex.disposables.Disposable;

class SubNavBar extends NavBar {

    private SubViewNavigator navigator;
    private Disposable subscription;

    SubNavBar(SubViewNavigator navigator) {
        this.navigator = navigator;
        addStyleName("sub-nav-bar");
        setWidth("100%");
        setDefaultComponentAlignment(Alignment.MIDDLE_CENTER);

        NativeButton backButton = new NativeButton("All patients", click -> navigator.close());
        backButton.setIcon(VaadinIcons.ARROW_LONG_LEFT);
        backButton.addStyleName("back-button");

        HorizontalLayout subPagesLayout = new HorizontalLayout();
        subPagesLayout.addStyleName("sub-pages");

        navButtons.put("profile", new NativeButton("Profile", click -> navigator.navigateTo("profile")));
        navButtons.put("journal", new NativeButton("Journal", click -> navigator.navigateTo("journal")));

        navButtons.forEach((name, button) -> {
            subPagesLayout.addComponent(button);
        });

        NativeButton editButton = new NativeButton("Edit", click -> navigator.navigateTo("profile/edit"));
        addComponents(backButton, subPagesLayout, editButton);

        setExpandRatio(subPagesLayout, 1);
        setComponentAlignment(subPagesLayout, Alignment.MIDDLE_CENTER);

    }

    @Override
    public void attach() {
        super.attach();

        subscription = navigator.getViewSubject().subscribe(v -> {
            navButtons.forEach((name, button) -> {
                if (name.equals(v.getUrl())) {
                    button.addStyleName("active");
                } else {
                    button.removeStyleName("active");
                }
            });
        });
    }

    @Override
    public void detach() {
        super.detach();

        subscription.dispose();
    }
}
