import {BaseAuthLayout} from "@/components/auth/wrappers";
import Footer from "./footer";


export default function Layout({children}: { children: React.ReactNode }) {
    return (
        <div className="flex flex-col min-h-dvh">
            {/*<Header hideNav="true"/>*/}
            <main className="flex-1 flex bg-background h-full items-center justify-center">
                <div className="container">
                    <div className="max-w-sm mx-auto">
                        <BaseAuthLayout>
                            {children}
                        </BaseAuthLayout>
                    </div>
                </div>
            </main>
            <Footer/>
        </div>
    );
}
