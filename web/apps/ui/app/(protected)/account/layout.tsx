import ProfileLayout from "@/components/account/profile-layout";

export default function Layout({children}: { children: React.ReactNode }) {
    return (
        <ProfileLayout>
            {children}
        </ProfileLayout>
    );
}
