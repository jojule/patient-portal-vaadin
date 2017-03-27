package com.vaadin.demo.ui.views.patients;

import com.vaadin.demo.ui.views.base.CssLayoutView;
import com.vaadin.demo.ui.views.patients.journal.JournalEditView;
import com.vaadin.demo.ui.views.patients.journal.JournalListingView;
import com.vaadin.demo.ui.views.patients.profile.ProfileEditView;
import com.vaadin.demo.ui.views.patients.profile.ProfileView;
import com.vaadin.server.Page;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.ui.CssLayout;
import org.springframework.beans.factory.annotation.Autowired;


@SpringComponent
public class PatientDetailsView extends CssLayoutView {

    private final PatientsService patientsService;
    private final SubViewNavigator navigator;
    private CssLayout content;


    @Autowired
    public PatientDetailsView(PatientsService patientsService, SubViewNavigator navigator, ProfileView profileView, ProfileEditView profileEditView, JournalListingView journalListingView, JournalEditView journalEditView) {
        this.navigator = navigator;
        addStyleName("patient-details-view");

        this.patientsService = patientsService;

        SubNavBar navBar = new SubNavBar(navigator);
        addComponent(navBar);
        content = new CssLayout();
        content.setSizeFull();
        addComponent(content);

        navigator.addViews(profileView, profileEditView, journalListingView, journalEditView);
        navigator.getViewSubject().subscribe(view -> {
            content.removeAllComponents();
            content.addComponent(view);
            Page.getCurrent().setTitle(view.getTitle());
            navBar.setVisible(!view.isFullScreen());
        });

        setSizeUndefined();
    }


    @Override
    public void attach() {
        super.attach();
        addSubscription(patientsService.getCurrentPatient().subscribe(maybePatient ->
                setVisibility(maybePatient.isPresent())));

        navigator.initFromUri();
    }

    private void setVisibility(boolean hasPatient) {
        if (hasPatient) {
            addStyleName("open");
        } else {
            removeStyleName("open");
        }
    }


}
