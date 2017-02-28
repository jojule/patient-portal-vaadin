package com.vaadin.demo.ui.mobile;

import com.vaadin.demo.entities.JournalEntry;
import com.vaadin.shared.ui.ContentMode;
import com.vaadin.ui.Label;
import com.vaadin.ui.VerticalLayout;

import java.text.SimpleDateFormat;

import static com.vaadin.shared.ui.ContentMode.PREFORMATTED;

/**
 * Created by mstahv
 */
public class MobileJournalRow extends MobileRow {

    private final JournalEntry journal;
    VerticalLayout details = new VerticalLayout();

    public MobileJournalRow(JournalEntry journal) {
        super(SimpleDateFormat.getDateInstance().format(journal.getDate()) + "\nDOCTOR",
                journal.getAppointmentType().toString() + "\n" + journal.getDoctor());
        this.journal = journal;
        header.setMargin(false);
        title.setContentMode(ContentMode.PREFORMATTED);
        desc.setContentMode(PREFORMATTED);

        setSpacing(false);

        details.setWidth("100%");
        Label detailsLabel = new Label(journal.getEntry());
        detailsLabel.setWidth("100%");
        detailsLabel.setCaption("Notes");
        details.addComponent(detailsLabel);
        details.setVisible(false);

        addComponent(details);
    }

    @Override
    protected void showDetails(boolean expanded) {
        details.setVisible(expanded);
    }
}
