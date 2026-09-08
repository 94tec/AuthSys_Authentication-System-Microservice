import {Navbar} from "@/components/layout/navbar";
import {Footer} from "@/components/layout/footer";
import {VisitorProvider} from "@/components/landing/visitor-provider";

export default function PublicLayout({
                                       children,
                                     }: {
  children: React.ReactNode;
}) {
  return (
      <VisitorProvider>
          <div className="flex min-h-screen flex-col bg-background">
            <Navbar />
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
      </VisitorProvider>
  );
}