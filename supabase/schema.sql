-- ============================================================
-- Reading practice: the whole database, for a Supabase project
-- of its own. Run once in the SQL Editor of a NEW project.
--
-- Accounts are Supabase Auth users (email + password).
--   profiles        one row per account: the name shown, and a code a parent uses to link the child
--   parent_links    which parent account may read which child account
--   reading_tries   one row per reading try
-- A reader sees only her own tries. A linked parent can read his
-- children's tries. Nobody can edit or delete a try from the page.
--
-- Every grant the page needs is written out below, so this works
-- whether or not the project grants API access to new tables
-- automatically (Supabase recommends turning that off).
-- ============================================================

GRANT USAGE ON SCHEMA public TO authenticated;

-- ---------- profiles ----------
CREATE TABLE IF NOT EXISTS public.profiles (
  id           UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 40),
  link_code    TEXT NOT NULL UNIQUE DEFAULT upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10)),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Own profile is readable" ON public.profiles;
CREATE POLICY "Own profile is readable" ON public.profiles
  FOR SELECT TO authenticated USING (auth.uid() = id);

DROP POLICY IF EXISTS "Own name is editable" ON public.profiles;
CREATE POLICY "Own name is editable" ON public.profiles
  FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- Only the name may be changed from the page; the code stays as issued.
REVOKE ALL ON public.profiles FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.profiles FROM authenticated;
GRANT SELECT ON public.profiles TO authenticated;
GRANT UPDATE (display_name) ON public.profiles TO authenticated;

-- A profile is created with every new account
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.profiles (id, display_name)
  VALUES (NEW.id, left(coalesce(NEW.raw_user_meta_data ->> 'display_name', ''), 40))
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ---------- parent links ----------
CREATE TABLE IF NOT EXISTS public.parent_links (
  parent_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  child_id   UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (parent_id, child_id),
  CHECK (parent_id <> child_id)
);

ALTER TABLE public.parent_links ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Links are visible to both sides" ON public.parent_links;
CREATE POLICY "Links are visible to both sides" ON public.parent_links
  FOR SELECT TO authenticated USING (auth.uid() = parent_id OR auth.uid() = child_id);

DROP POLICY IF EXISTS "Either side can remove a link" ON public.parent_links;
CREATE POLICY "Either side can remove a link" ON public.parent_links
  FOR DELETE TO authenticated USING (auth.uid() = parent_id OR auth.uid() = child_id);

REVOKE ALL ON public.parent_links FROM anon;
REVOKE INSERT, UPDATE ON public.parent_links FROM authenticated;   -- links are made only through add_child_by_code
GRANT SELECT, DELETE ON public.parent_links TO authenticated;

-- Link a child by the code shown on her own screen. Returns her name, or NULL when the code is unknown.
CREATE OR REPLACE FUNCTION public.add_child_by_code(p_code TEXT)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_child UUID; v_name TEXT;
BEGIN
  IF auth.uid() IS NULL OR p_code IS NULL OR char_length(trim(p_code)) < 8 THEN RETURN NULL; END IF;
  SELECT id, display_name INTO v_child, v_name
  FROM profiles WHERE link_code = upper(trim(p_code));
  IF v_child IS NULL OR v_child = auth.uid() THEN RETURN NULL; END IF;
  INSERT INTO parent_links (parent_id, child_id) VALUES (auth.uid(), v_child) ON CONFLICT DO NOTHING;
  RETURN coalesce(nullif(v_name, ''), 'ילדה');
END; $$;

-- The children linked to the signed-in parent
CREATE OR REPLACE FUNCTION public.my_children()
RETURNS TABLE (child_id UUID, display_name TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.display_name
  FROM parent_links pl JOIN profiles p ON p.id = pl.child_id
  WHERE pl.parent_id = auth.uid()
  ORDER BY p.display_name;
$$;

-- ---------- reading tries ----------
CREATE TABLE IF NOT EXISTS public.reading_tries (
  id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id  UUID NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  read_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  passage  TEXT NOT NULL CHECK (char_length(passage) BETWEEN 1 AND 400),
  words    INT  NOT NULL CHECK (words BETWEEN 1 AND 400),
  good     INT  NOT NULL CHECK (good BETWEEN 0 AND 400),
  miss     TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(miss) <= 80),
  near     TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(near) <= 80),
  skipped  TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(skipped) <= 80),
  helped   TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(helped) <= 80),
  stuck    TEXT NOT NULL DEFAULT '' CHECK (char_length(stuck) <= 60),
  ms       INT  NOT NULL DEFAULT 0 CHECK (ms BETWEEN 0 AND 3600000),
  stars    SMALLINT NOT NULL DEFAULT 0 CHECK (stars BETWEEN 0 AND 3),
  done     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS reading_tries_user_time ON public.reading_tries (user_id, read_at DESC);

ALTER TABLE public.reading_tries ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Readers add own tries" ON public.reading_tries;
CREATE POLICY "Readers add own tries" ON public.reading_tries
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Readers view own tries" ON public.reading_tries;
CREATE POLICY "Readers view own tries" ON public.reading_tries
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

REVOKE ALL ON public.reading_tries FROM anon;
REVOKE UPDATE, DELETE ON public.reading_tries FROM authenticated;   -- a try is a log entry
GRANT SELECT, INSERT ON public.reading_tries TO authenticated;

-- A linked child's tries, for her parent
CREATE OR REPLACE FUNCTION public.child_reading_tries(p_child UUID)
RETURNS SETOF public.reading_tries
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT t.*
  FROM reading_tries t
  WHERE t.user_id = p_child
    AND EXISTS (SELECT 1 FROM parent_links WHERE parent_id = auth.uid() AND child_id = p_child)
  ORDER BY t.read_at DESC
  LIMIT 1000;
$$;

-- Functions are for signed-in accounts only
REVOKE ALL ON FUNCTION public.add_child_by_code(TEXT)   FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.my_children()             FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.child_reading_tries(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.handle_new_user()         FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.add_child_by_code(TEXT)   TO authenticated;
GRANT EXECUTE ON FUNCTION public.my_children()             TO authenticated;
GRANT EXECUTE ON FUNCTION public.child_reading_tries(UUID) TO authenticated;
