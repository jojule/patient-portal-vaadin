package com.vaadin.demo.ui.views.patients;

import com.vaadin.icons.VaadinIcons;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;


public class SubViewHeader extends HorizontalLayout {

    public SubViewHeader(SubViewNavigator navigator, String heading, String closeLink) {
        addStyleName("sub-view-header");
        setMargin(false);

        Label text = new Label(heading);
        text.addStyleName(ValoTheme.LABEL_H1);
        NativeButton close = new NativeButton();
        close.addClickListener(click -> navigator.navigateTo(closeLink));
        close.setIcon(VaadinIcons.CLOSE);

        setWidth("100%");
        addComponents(text, close);
        setExpandRatio(text, 1);
        setComponentAlignment(text, Alignment.MIDDLE_CENTER);
    }
}
