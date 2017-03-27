package com.vaadin.demo.ui.views.patients.journal;


import com.vaadin.demo.entities.JournalEntry;
import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.service.PatientService;
import com.vaadin.demo.ui.views.base.VerticalLayoutView;
import com.vaadin.demo.ui.views.patients.PatientsService;
import com.vaadin.demo.ui.views.patients.SubView;
import com.vaadin.demo.ui.views.patients.SubViewNavigator;
import com.vaadin.icons.VaadinIcons;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.ViewScope;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;
import io.reactivex.disposables.Disposable;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.SimpleDateFormat;

@SpringComponent
@ViewScope
public class JournalListingView extends VerticalLayoutView implements SubView {


    private final PatientsService patientsService;
    private PatientService patientService;
    private SubViewNavigator navigator;
    private Grid<JournalEntry> journalGrid;
    private Label nameLabel;

    @Override
    public String getUrl() {
        return "journal";
    }

    @Override
    public String getTitle() {
        return "Patient Journal";
    }

    @Override
    public boolean isFullScreen() {
        return false;
    }


    @Autowired
    public JournalListingView(PatientsService patientsService, PatientService patientService, SubViewNavigator navigator) {
        this.patientsService = patientsService;
        this.patientService = patientService;
        this.navigator = navigator;

        addHeaderLayout();
        addGrid();
    }

    private void addHeaderLayout() {
        HorizontalLayout headerLayout = new HorizontalLayout();
        headerLayout.setDefaultComponentAlignment(Alignment.MIDDLE_LEFT);
        nameLabel = new Label();
        nameLabel.addStyleName(ValoTheme.LABEL_H2);
        Button addButton = new NativeButton("New Entry", click -> navigator.navigateTo("journal/new"));
        addButton.addStyleName(ValoTheme.BUTTON_PRIMARY);
        addButton.setIcon(VaadinIcons.PLUS);
        headerLayout.addComponentsAndExpand(nameLabel);
        headerLayout.addComponent(addButton);
        addComponent(headerLayout);
    }

    private void addGrid() {
        journalGrid = new Grid<>();
        journalGrid.setSizeFull();
        journalGrid.addColumn(entry -> SimpleDateFormat.getDateInstance().format(entry.getDate())).setCaption("Date");
        journalGrid.addColumn(entry -> entry.getAppointmentType().toString()).setCaption("Appointment");
        journalGrid.addColumn(entry -> entry.getDoctor().toString()).setCaption("Doctor").setExpandRatio(1);
        journalGrid.addColumn(JournalEntry::getEntry).setCaption("Notes").setExpandRatio(1).setMaximumWidth(400);

        journalGrid.setDetailsGenerator(j -> {
            Label notesLabel = new Label(j.getEntry());
            notesLabel.setWidth("100%");
            notesLabel.setCaption("NOTES");
            return new VerticalLayout(notesLabel);
        });

        journalGrid.addItemClickListener(e ->
                journalGrid.setDetailsVisible(e.getItem(), !journalGrid.isDetailsVisible(e.getItem())));
        addComponentsAndExpand(journalGrid);
    }


    private void updateFromPatient(Patient patient) {
        journalGrid.setItems(patient.getJournalEntries());
        nameLabel.setValue(patient.getFirstName() + " " + patient.getLastName());
    }

    @Override
    public void attach() {
        super.attach();

        addSubscription(patientsService.getCurrentPatient().distinct().subscribe(patient ->
                patient.ifPresent(p -> updateFromPatient(patientService.findAttached(p)))
        ));
    }

}
