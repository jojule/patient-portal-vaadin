package com.vaadin.demo.ui.views;

import com.vaadin.navigator.View;
import com.vaadin.navigator.ViewChangeListener;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.UIScope;
import com.vaadin.ui.Alignment;
import com.vaadin.ui.Label;
import com.vaadin.ui.VerticalLayout;
import com.vaadin.ui.themes.ValoTheme;

@SpringComponent
@UIScope
public class ErrorView extends VerticalLayout implements View {

    public ErrorView() {
        setSizeFull();
        setDefaultComponentAlignment(Alignment.MIDDLE_CENTER);

        Label failMessage = new Label("You failed.");
        failMessage.addStyleName(ValoTheme.LABEL_H1);
        addComponent(failMessage);
    }

    @Override
    public void enter(ViewChangeListener.ViewChangeEvent event) {

    }
}
