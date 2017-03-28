package com.vaadin.demo.ui.views;

import com.vaadin.navigator.Navigator;
import com.vaadin.navigator.View;
import com.vaadin.navigator.ViewDisplay;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.SpringViewDisplay;
import com.vaadin.spring.annotation.UIScope;
import com.vaadin.spring.navigator.SpringNavigator;
import com.vaadin.spring.navigator.SpringViewProvider;
import com.vaadin.ui.Component;
import com.vaadin.ui.CssLayout;
import com.vaadin.ui.VerticalLayout;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

@SpringComponent
@UIScope
@SpringViewDisplay
public class MainView extends VerticalLayout implements ViewDisplay {

    private CssLayout content = new CssLayout();

    @Autowired
    public MainView(SpringNavigator navigator) {
        navigator.setErrorView(ErrorView.class);
    }

    @PostConstruct
    void init() {
        addStyleName("main");
        setSizeFull();
        setMargin(false);

        addComponent(new MainNavBar());
        addComponentsAndExpand(content);
        content.setSizeFull();
    }

    @Override
    public void attach() {
        super.attach();

        setupNavigator();
    }

    private void setupNavigator() {
        Navigator navigator = getUI().getNavigator();

        if (!navigator.getState().isEmpty()) {
            navigator.navigateTo(navigator.getState());
        } else {
            navigator.navigateTo("patients");
        }
    }

    @Override
    public void showView(View view) {
        content.removeAllComponents();
        content.addComponent((Component) view);
    }
}
