public class ManagedStacks {
    static void leaf() throws InterruptedException {
        System.out.println("JAVA_READY");
        Thread.sleep(30000);
    }
    static void caller() throws InterruptedException { leaf(); }
    public static void main(String[] args) throws InterruptedException { caller(); }
}
