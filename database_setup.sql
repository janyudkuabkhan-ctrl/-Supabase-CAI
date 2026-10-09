-- ==========================================
-- 1. EXTENSIONS & SCHEMA SETUP
-- ==========================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================
-- 2. TABLES CREATION
-- ==========================================
CREATE TABLE public.teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);

CREATE TABLE public.students (
    id VARCHAR(11) PRIMARY KEY,
    title VARCHAR(20) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    section VARCHAR(10) NOT NULL,
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT
);

CREATE TABLE public.attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(4) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (user_id, kind)
);

CREATE TABLE public.progress (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL CHECK (unit BETWEEN 1 AND 5),
    done BOOLEAN DEFAULT FALSE,
    UNIQUE (user_id, unit)
);

CREATE TABLE public.submissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER NULL,
    teacher_comment TEXT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE public.materials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title TEXT NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==========================================
-- 3. SECURITY DEFINER FUNCTIONS
-- ==========================================
-- Check if current user is teacher
CREATE OR REPLACE FUNCTION public.is_teacher() 
RETURNS BOOLEAN 
LANGUAGE sql 
SECURITY DEFINER 
SET search_path = public 
AS $$
    SELECT EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
$$;

-- View for teacher dashboard (Security Invoker)
CREATE OR REPLACE VIEW public.results WITH (security_invoker = true) AS
SELECT 
    s.id AS student_id, s.title, s.first_name, s.last_name, s.section, s.photo_path,
    u.email, s.user_id,
    MAX(CASE WHEN a.kind = 'pre' THEN a.score END) AS pre_score,
    MAX(CASE WHEN a.kind = 'post' THEN a.score END) AS post_score,
    COUNT(p.id) AS units_completed
FROM public.students s
LEFT JOIN auth.users u ON s.user_id = u.id
LEFT JOIN public.attempts a ON s.user_id = a.user_id
LEFT JOIN public.progress p ON s.user_id = p.user_id AND p.done = true
WHERE s.user_id IS NOT NULL
GROUP BY s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path, u.email, s.user_id;

-- ==========================================
-- 4. TRIGGERS
-- ==========================================
-- Trigger 1: Auto-link new auth.user to student whitelist OR allow teacher
CREATE OR REPLACE FUNCTION public.handle_new_user() 
RETURNS trigger 
LANGUAGE plpgsql 
SECURITY DEFINER 
SET search_path = public 
AS $$
DECLARE
    email_prefix VARCHAR;
BEGIN
    email_prefix := split_part(NEW.email, '@', 1);
    
    -- If email starts with 11 digits (Student)
    IF email_prefix ~ '^\d{11}$' THEN
        -- Check if student exists and not linked
        IF EXISTS (SELECT 1 FROM students WHERE id = email_prefix AND user_id IS NULL) THEN
            UPDATE students SET user_id = NEW.id WHERE id = email_prefix;
            RETURN NEW;
        ELSE
            RAISE EXCEPTION 'รหัสนักศึกษานี้ไม่อยู่ในระบบ หรือถูกลงทะเบียนไปแล้ว';
        END IF;
    ELSE
        -- Allow registration (Teacher will be assigned manually later)
        RETURN NEW;
    END IF;
END;
$$;

CREATE TRIGGER on_auth_user_created
    BEFORE INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Trigger 2: Prevent student from updating submission score/comment
CREATE OR REPLACE FUNCTION public.lock_submission_scores()
RETURNS trigger 
LANGUAGE plpgsql 
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF NOT is_teacher() THEN
        NEW.score = OLD.score;
        NEW.teacher_comment = OLD.teacher_comment;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER prevent_student_grading
    BEFORE UPDATE ON public.submissions
    FOR EACH ROW EXECUTE FUNCTION public.lock_submission_scores();

-- ==========================================
-- 5. ROW LEVEL SECURITY (RLS)
-- ==========================================
-- Revoke all from anon
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;

-- Enable RLS
ALTER TABLE public.teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.students ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.materials ENABLE ROW LEVEL SECURITY;

-- Teachers Table: Only teacher sees themselves
CREATE POLICY "Teacher read self" ON public.teachers FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- Students Table: 
-- Teacher reads all. Student reads all (for UI context) but only updates their own photo.
CREATE POLICY "Teacher read all students" ON public.students FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read self" ON public.students FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Student update photo" ON public.students FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Attempts Table:
CREATE POLICY "Teacher read all attempts" ON public.attempts FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student CRUD own attempts" ON public.attempts FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Progress Table:
CREATE POLICY "Teacher read all progress" ON public.progress FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student CRUD own progress" ON public.progress FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Submissions Table:
CREATE POLICY "Teacher read update all submissions" ON public.submissions FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());
CREATE POLICY "Student CRUD own submissions" ON public.submissions FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Materials Table:
CREATE POLICY "All auth read materials" ON public.materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teacher CRUD materials" ON public.materials FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- ==========================================
-- 6. STORAGE SETUP
-- ==========================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types) VALUES 
('photos', 'photos', false, 2097152, ARRAY['image/png', 'image/jpeg']), -- 2MB
('submissions', 'submissions', false, 20971520, ARRAY['image/png', 'image/jpeg', 'application/pdf', 'video/mp4']), -- 20MB
('materials', 'materials', false, 52428800, ARRAY['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']); -- 50MB

-- Storage RLS (Requires enabling on storage.objects)
-- Photos: User controls their UUID folder, Teacher reads all
CREATE POLICY "User manage own photo" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text) WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Teacher read photos" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND is_teacher());

-- Submissions: Same as photos
CREATE POLICY "User manage own submission" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text) WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Teacher read submissions" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND is_teacher());

-- Materials: Everyone reads, Teacher writes
CREATE POLICY "Auth read materials" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Teacher manage materials" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND is_teacher()) WITH CHECK (bucket_id = 'materials' AND is_teacher());

-- ==========================================
-- 7. DUMMY DATA & TEACHER SETUP
-- ==========================================
-- Mock 6 Students (For importing real data, use Supabase Table Editor via CSV)
INSERT INTO public.students (id, title, first_name, last_name, section) VALUES
('11111111111', 'นาย', 'สมชาย', 'เรียนดี', '01'),
('11111111112', 'นางสาว', 'สมหญิง', 'ขยันยิ่ง', '01'),
('11111111113', 'นาย', 'ปิติ', 'มีมานะ', '02'),
('11111111114', 'นางสาว', 'มานี', 'ชูใจ', '02'),
('11111111115', 'นาย', 'วีระ', 'รักเรียน', '01'),
('11111111116', 'นางสาว', 'ชูติมา', 'ก้าวหน้า', '02');

-- [ACTION REQUIRED FOR TEACHER SETUP]
-- 1. Sign up the teacher via the App UI with a non-11-digit email (e.g., teacher@edu.ac.th)
-- 2. Uncomment the lines below, replace the email, and run in SQL Editor to grant teacher role.
/*
DO $$
DECLARE
    t_id UUID;
BEGIN
    SELECT id INTO t_id FROM auth.users WHERE email = 'teacher@dummy-edu.ac.th';
    IF t_id IS NOT NULL THEN
        INSERT INTO public.teachers (user_id) VALUES (t_id) ON CONFLICT DO NOTHING;
    END IF;
END $$;
*/