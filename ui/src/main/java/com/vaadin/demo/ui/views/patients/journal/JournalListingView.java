package com.vaadin.demo.ui.views.patients.journal;


import com.vaadin.demo.entities.JournalEntry;
import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.service.PatientService;
import com.vaadin.demo.ui.service.PatientsService;
import com.vaadin.demo.ui.views.base.Responsive;
import com.vaadin.demo.ui.views.base.VerticalLayoutView;
import com.vaadin.demo.ui.views.patients.SubView;
import com.vaadin.demo.ui.views.patients.SubViewNavigator;
import com.vaadin.icons.VaadinIcons;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.ViewScope;
import com.vaadin.ui.*;
import com.vaadin.ui.renderers.ComponentRenderer;
import com.vaadin.ui.themes.ValoTheme;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

@SpringComponent
@ViewScope
public class JournalListingView extends VerticalLayoutView implements SubView, Responsive {
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

    @Override
    public void attach() {
        super.attach();

        addDetachListener(addResponsiveListener(mode -> {
            if (mode == Mode.NARROW) {
                setupNarrowGrid();
            } else if (mode == Mode.WIDE) {
                setupWideGrid();
            }
        }));

        addSubscription(patientsService.getCurrentPatient().subscribe(patient ->
                patient.ifPresent(p -> updateFromPatient(patientService.findAttached(p)))
        ));
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
        addComponentsAndExpand(journalGrid);
    }

    private void setupNarrowGrid() {
        journalGrid.getDataProvider().refreshAll();
        journalGrid.removeAllColumns();

        journalGrid.addColumn(patient -> {
            NativeButton toggleButton = new NativeButton();
            toggleButton.setIcon(VaadinIcons.CHEVRON_RIGHT);
            toggleButton.addClickListener(click -> {
                boolean visible = !journalGrid.isDetailsVisible(patient);
                journalGrid.setDetailsVisible(patient, visible);
                // Changing the icon doesn't get updated on the client for some reason
                toggleButton.setIcon(visible ? VaadinIcons.CHEVRON_DOWN : VaadinIcons.CHEVRON_RIGHT);
            });
            return toggleButton;
        }, new ComponentRenderer());
        journalGrid.addColumn(entry -> SimpleDateFormat.getDateInstance(DateFormat.MEDIUM).format(entry.getDate())).setCaption("Date");
        journalGrid.addColumn(entry -> entry.getAppointmentType().toString()).setCaption("Appointment");

        journalGrid.setDetailsGenerator(entry -> {
            Label doctorLabel = new Label(entry.getDoctor().getLastName() + ", " + entry.getDoctor().getFirstName());
            doctorLabel.setCaption("Doctor");
            Label notesLabel = new Label(entry.getEntry());
            notesLabel.setWidth("100%");
            notesLabel.setCaption("NOTES");
            FormLayout layout = new FormLayout(doctorLabel, notesLabel);
            layout.setMargin(true);
            return layout;
        });
    }

    private void setupWideGrid() {
        journalGrid.removeAllColumns();
        journalGrid.addColumn(entry -> SimpleDateFormat.getDateInstance().format(entry.getDate())).setCaption("Date");
        journalGrid.addColumn(entry -> entry.getAppointmentType().toString()).setCaption("Appointment");
        journalGrid.addColumn(entry -> entry.getDoctor().toString()).setCaption("Doctor").setExpandRatio(1);
        journalGrid.addColumn(JournalEntry::getEntry).setCaption("Notes").setExpandRatio(1).setMaximumWidth(400);

        journalGrid.setDetailsGenerator(entry -> {
            Label notesLabel = new Label(entry.getEntry());
            notesLabel.setWidth("100%");
            notesLabel.setCaption("NOTES");
            return new VerticalLayout(notesLabel);
        });

        journalGrid.addItemClickListener(e ->
                journalGrid.setDetailsVisible(e.getItem(), !journalGrid.isDetailsVisible(e.getItem())));

        journalGrid.getDataProvider().refreshAll();
    }


    private void updateFromPatient(Patient patient) {
        journalGrid.setItems(patient.getJournalEntries());
        nameLabel.setValue(patient.getFirstName() + " " + patient.getLastName());
    }



}
