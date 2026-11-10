import org.dcm4che3.net.ApplicationEntity;
import org.dcm4che3.net.Association;
import org.dcm4che3.net.Connection;
import org.dcm4che3.net.pdu.AAssociateRQ;

/*
 * The shapes dcm4che code actually writes. Modelled on dcm4che's own tools (storescu, findscu,
 * syslog, hl7snd), where the AE is constructed by hand, the association is opened from it, and
 * setProtocol is the only call that ever names something other than DICOM.
 */
public class Dcm4cheDicomUsage {

    /* An SCU: the AE title is the DICOM identity this code presents. */
    public ApplicationEntity scu() {
        return new ApplicationEntity("STORESCU"); // Noncompliant {{(Protocol) DICOM}}
    }

    /* The no-argument form, used where the title is set later from configuration. */
    public ApplicationEntity blankAe() {
        return new ApplicationEntity(); // Noncompliant {{(Protocol) DICOM}}
    }

    /* Opening the association: the two-argument overload dcm4che's tools use. */
    public Association openAssociation(ApplicationEntity ae, Connection remote, AAssociateRQ rq)
            throws Exception {
        return ae.connect(remote, rq); // Noncompliant {{(Protocol) DICOM}}
    }

    /* The three-argument overload, with the local connection given explicitly. */
    public Association openAssociationFromLocal(
            ApplicationEntity ae, Connection local, Connection remote, AAssociateRQ rq)
            throws Exception {
        return ae.connect(local, remote, rq); // Noncompliant {{(Protocol) DICOM}}
    }

    /* The overload that takes the remote AE rather than its connection. */
    public Association openAssociationToAe(
            ApplicationEntity ae, ApplicationEntity remoteAe, AAssociateRQ rq) throws Exception {
        return ae.connect(remoteAe, rq); // Noncompliant {{(Protocol) DICOM}}
    }

    /* A DICOM connection, stated rather than left to the default. */
    public void dicomConnection(Connection conn) {
        conn.setProtocol(Connection.Protocol.DICOM); // Noncompliant {{(Protocol) DICOM}}
    }

    /* HL7 over MLLP: the same device, a different protocol. dcm4che's hl7snd does this. */
    public void hl7Connection(Connection conn) {
        conn.setProtocol(Connection.Protocol.HL7); // Noncompliant {{(Protocol) HL7}}
    }

    /* MLLP release 2 is a framing of HL7, so it is the same protocol. */
    public void hl7Mllp2Connection(Connection conn) {
        conn.setProtocol(Connection.Protocol.HL7_MLLP2); // Noncompliant {{(Protocol) HL7}}
    }

    /* Syslog over TLS: the one member that states transport security as well. */
    public void syslogTlsConnection(Connection conn) {
        conn.setProtocol(Connection.Protocol.SYSLOG_TLS); // Noncompliant {{(Protocol) Syslog}}
    }

    /* Plain syslog over UDP, with nothing protecting it. */
    public void syslogUdpConnection(Connection conn) {
        conn.setProtocol(Connection.Protocol.SYSLOG_UDP); // Noncompliant {{(Protocol) Syslog}}
    }

    /* The web protocol, for a device that also serves DICOMweb. */
    public void httpConnection(Connection conn) {
        conn.setProtocol(Connection.Protocol.HTTP); // Noncompliant {{(Protocol) HTTP}}
    }

    /* Counter-check: the protocol comes from a parameter, so none may be invented. */
    public void protocolFromParameter(Connection conn, Connection.Protocol protocol) {
        conn.setProtocol(protocol);
    }

    /* Counter-check: dcm4che's LDAP and JSON config read the protocol by name at runtime. */
    public void protocolFromString(Connection conn, String configured) {
        conn.setProtocol(Connection.Protocol.valueOf(configured));
    }
}
