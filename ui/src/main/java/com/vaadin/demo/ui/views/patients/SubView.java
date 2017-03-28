package com.vaadin.demo.ui.views.patients;


import com.vaadin.ui.Component;

public interface SubView extends Component {
    String getUrl();

    String getTitle();

    boolean isFullScreen();
}
