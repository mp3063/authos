--
-- PostgreSQL database dump
--

-- Dumped from database version 16.9 (Homebrew)
-- Dumped by pg_dump version 16.9 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activity_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activity_log (
    id bigint NOT NULL,
    log_name character varying(255),
    description text NOT NULL,
    subject_type character varying(255),
    subject_id bigint,
    event character varying(255),
    causer_type character varying(255),
    causer_id bigint,
    properties json,
    batch_uuid uuid,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: activity_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.activity_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: activity_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.activity_log_id_seq OWNED BY public.activity_log.id;


--
-- Name: application_group_applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_group_applications (
    id bigint NOT NULL,
    application_group_id bigint NOT NULL,
    application_id bigint NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: application_group_applications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.application_group_applications_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: application_group_applications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.application_group_applications_id_seq OWNED BY public.application_group_applications.id;


--
-- Name: application_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application_groups (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    parent_id bigint,
    is_active boolean DEFAULT true NOT NULL,
    settings json,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: application_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.application_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: application_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.application_groups_id_seq OWNED BY public.application_groups.id;


--
-- Name: applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.applications (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret character varying(255) NOT NULL,
    redirect_uris json NOT NULL,
    allowed_origins json,
    allowed_grant_types json NOT NULL,
    webhook_url character varying(255),
    settings json,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone,
    passport_client_id character varying(255),
    scopes json
);


--
-- Name: applications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.applications_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: applications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.applications_id_seq OWNED BY public.applications.id;


--
-- Name: authentication_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authentication_logs (
    id bigint NOT NULL,
    user_id bigint,
    application_id bigint,
    event character varying(255) NOT NULL,
    success boolean DEFAULT true NOT NULL,
    ip_address character varying(255) NOT NULL,
    user_agent text NOT NULL,
    details json,
    metadata json,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: authentication_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.authentication_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: authentication_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.authentication_logs_id_seq OWNED BY public.authentication_logs.id;


--
-- Name: cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cache (
    key character varying(255) NOT NULL,
    value text NOT NULL,
    expiration integer NOT NULL
);


--
-- Name: cache_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cache_locks (
    key character varying(255) NOT NULL,
    owner character varying(255) NOT NULL,
    expiration integer NOT NULL
);


--
-- Name: custom_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_roles (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    display_name character varying(255),
    description text,
    permissions jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    created_by bigint,
    is_active boolean DEFAULT true NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone,
    deleted_at timestamp(0) without time zone
);


--
-- Name: custom_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.custom_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: custom_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.custom_roles_id_seq OWNED BY public.custom_roles.id;


--
-- Name: failed_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.failed_jobs (
    id bigint NOT NULL,
    uuid character varying(255) NOT NULL,
    connection text NOT NULL,
    queue text NOT NULL,
    payload text NOT NULL,
    exception text NOT NULL,
    failed_at timestamp(0) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: failed_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.failed_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: failed_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.failed_jobs_id_seq OWNED BY public.failed_jobs.id;


--
-- Name: invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invitations (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    inviter_id bigint NOT NULL,
    email character varying(255) NOT NULL,
    token character varying(255) NOT NULL,
    role character varying(255) DEFAULT 'user'::character varying NOT NULL,
    expires_at timestamp(0) without time zone NOT NULL,
    status character varying(255) DEFAULT 'pending'::character varying NOT NULL,
    metadata json,
    accepted_by bigint,
    accepted_at timestamp(0) without time zone,
    declined_at timestamp(0) without time zone,
    decline_reason text,
    cancelled_by bigint,
    cancelled_at timestamp(0) without time zone,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone,
    CONSTRAINT invitations_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'accepted'::character varying, 'declined'::character varying, 'cancelled'::character varying, 'expired'::character varying])::text[])))
);


--
-- Name: invitations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.invitations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: invitations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.invitations_id_seq OWNED BY public.invitations.id;


--
-- Name: job_batches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.job_batches (
    id character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    total_jobs integer NOT NULL,
    pending_jobs integer NOT NULL,
    failed_jobs integer NOT NULL,
    failed_job_ids text NOT NULL,
    options text,
    cancelled_at integer,
    created_at integer NOT NULL,
    finished_at integer
);


--
-- Name: jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jobs (
    id bigint NOT NULL,
    queue character varying(255) NOT NULL,
    payload text NOT NULL,
    attempts smallint NOT NULL,
    reserved_at integer,
    available_at integer NOT NULL,
    created_at integer NOT NULL
);


--
-- Name: jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.jobs_id_seq OWNED BY public.jobs.id;


--
-- Name: migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.migrations (
    id integer NOT NULL,
    migration character varying(255) NOT NULL,
    batch integer NOT NULL
);


--
-- Name: migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.migrations_id_seq OWNED BY public.migrations.id;


--
-- Name: model_has_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.model_has_permissions (
    permission_id bigint NOT NULL,
    model_type character varying(255) NOT NULL,
    model_id bigint NOT NULL,
    organization_id bigint
);


--
-- Name: model_has_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.model_has_roles (
    role_id bigint NOT NULL,
    model_type character varying(255) NOT NULL,
    model_id bigint NOT NULL,
    organization_id bigint
);


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    id uuid NOT NULL,
    type character varying(255) NOT NULL,
    notifiable_type character varying(255) NOT NULL,
    notifiable_id bigint NOT NULL,
    data jsonb NOT NULL,
    read_at timestamp(0) without time zone,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: oauth_access_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_access_tokens (
    id character(80) NOT NULL,
    user_id bigint,
    client_id uuid NOT NULL,
    name character varying(255),
    scopes text,
    revoked boolean NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone,
    expires_at timestamp(0) without time zone
);


--
-- Name: oauth_auth_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_auth_codes (
    id character(80) NOT NULL,
    user_id bigint NOT NULL,
    client_id uuid NOT NULL,
    scopes text,
    revoked boolean NOT NULL,
    expires_at timestamp(0) without time zone
);


--
-- Name: oauth_authorization_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_authorization_codes (
    id character varying(100) NOT NULL,
    user_id bigint NOT NULL,
    client_id uuid NOT NULL,
    scopes json,
    redirect_uri text NOT NULL,
    code_challenge character varying(128),
    code_challenge_method character varying(10),
    state character varying(512),
    revoked boolean DEFAULT false NOT NULL,
    expires_at timestamp(0) without time zone NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: oauth_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_clients (
    id uuid NOT NULL,
    owner_type character varying(255),
    owner_id bigint,
    name character varying(255) NOT NULL,
    secret character varying(255),
    provider character varying(255),
    redirect text NOT NULL,
    personal_access_client boolean NOT NULL,
    password_client boolean NOT NULL,
    revoked boolean NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: oauth_device_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_device_codes (
    id character(80) NOT NULL,
    user_id bigint,
    client_id uuid NOT NULL,
    user_code character(8) NOT NULL,
    scopes text NOT NULL,
    revoked boolean NOT NULL,
    user_approved_at timestamp(0) without time zone,
    last_polled_at timestamp(0) without time zone,
    expires_at timestamp(0) without time zone
);


--
-- Name: oauth_refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_refresh_tokens (
    id character(80) NOT NULL,
    access_token_id character(80) NOT NULL,
    revoked boolean NOT NULL,
    expires_at timestamp(0) without time zone,
    user_id bigint,
    client_id uuid,
    scopes json
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    description text,
    website character varying(255),
    settings json,
    logo character varying(255),
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone,
    deleted_at timestamp(0) without time zone
);


--
-- Name: organizations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.organizations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: organizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.organizations_id_seq OWNED BY public.organizations.id;


--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_tokens (
    email character varying(255) NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp(0) without time zone
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    id bigint NOT NULL,
    organization_id bigint,
    name character varying(255) NOT NULL,
    guard_name character varying(255) NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.permissions_id_seq OWNED BY public.permissions.id;


--
-- Name: role_has_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_has_permissions (
    permission_id bigint NOT NULL,
    role_id bigint NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id bigint NOT NULL,
    organization_id bigint,
    name character varying(255) NOT NULL,
    guard_name character varying(255) NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id character varying(255) NOT NULL,
    user_id bigint,
    ip_address character varying(45),
    user_agent text,
    payload text NOT NULL,
    last_activity integer NOT NULL
);


--
-- Name: sso_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sso_configurations (
    id bigint NOT NULL,
    application_id bigint NOT NULL,
    name character varying(255),
    provider character varying(255),
    logout_url character varying(255) NOT NULL,
    callback_url character varying(255) NOT NULL,
    allowed_domains json NOT NULL,
    session_lifetime integer DEFAULT 3600 NOT NULL,
    settings json,
    configuration json,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: sso_configurations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sso_configurations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sso_configurations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sso_configurations_id_seq OWNED BY public.sso_configurations.id;


--
-- Name: sso_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sso_sessions (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    application_id bigint NOT NULL,
    session_token character varying(255) NOT NULL,
    refresh_token character varying(255) NOT NULL,
    external_session_id character varying(255),
    ip_address inet NOT NULL,
    user_agent text NOT NULL,
    expires_at timestamp(0) without time zone NOT NULL,
    last_activity_at timestamp(0) without time zone NOT NULL,
    logged_out_at timestamp(0) without time zone,
    logged_out_by bigint,
    metadata json,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: sso_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sso_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sso_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sso_sessions_id_seq OWNED BY public.sso_sessions.id;


--
-- Name: user_applications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_applications (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    application_id bigint NOT NULL,
    granted_by bigint,
    granted_at timestamp(0) without time zone,
    metadata json,
    permissions json,
    last_login_at timestamp(0) without time zone,
    login_count integer DEFAULT 0 NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: user_applications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_applications_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_applications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_applications_id_seq OWNED BY public.user_applications.id;


--
-- Name: user_custom_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_custom_roles (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    custom_role_id bigint NOT NULL,
    granted_at timestamp(0) without time zone,
    granted_by bigint,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: user_custom_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_custom_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_custom_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_custom_roles_id_seq OWNED BY public.user_custom_roles.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    avatar character varying(255),
    profile json,
    organization_id bigint,
    password_changed_at timestamp(0) without time zone,
    is_active boolean DEFAULT true NOT NULL,
    provider character varying(255),
    provider_id character varying(255),
    provider_token text,
    provider_refresh_token text,
    provider_data json,
    email_verified_at timestamp(0) without time zone,
    password character varying(255),
    remember_token character varying(100),
    two_factor_secret character varying(255),
    two_factor_recovery_codes text,
    two_factor_confirmed_at timestamp(0) without time zone,
    mfa_methods json,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: activity_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activity_log ALTER COLUMN id SET DEFAULT nextval('public.activity_log_id_seq'::regclass);


--
-- Name: application_group_applications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_group_applications ALTER COLUMN id SET DEFAULT nextval('public.application_group_applications_id_seq'::regclass);


--
-- Name: application_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_groups ALTER COLUMN id SET DEFAULT nextval('public.application_groups_id_seq'::regclass);


--
-- Name: applications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications ALTER COLUMN id SET DEFAULT nextval('public.applications_id_seq'::regclass);


--
-- Name: authentication_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authentication_logs ALTER COLUMN id SET DEFAULT nextval('public.authentication_logs_id_seq'::regclass);


--
-- Name: custom_roles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles ALTER COLUMN id SET DEFAULT nextval('public.custom_roles_id_seq'::regclass);


--
-- Name: failed_jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.failed_jobs ALTER COLUMN id SET DEFAULT nextval('public.failed_jobs_id_seq'::regclass);


--
-- Name: invitations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations ALTER COLUMN id SET DEFAULT nextval('public.invitations_id_seq'::regclass);


--
-- Name: jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs ALTER COLUMN id SET DEFAULT nextval('public.jobs_id_seq'::regclass);


--
-- Name: migrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migrations ALTER COLUMN id SET DEFAULT nextval('public.migrations_id_seq'::regclass);


--
-- Name: organizations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations ALTER COLUMN id SET DEFAULT nextval('public.organizations_id_seq'::regclass);


--
-- Name: permissions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions ALTER COLUMN id SET DEFAULT nextval('public.permissions_id_seq'::regclass);


--
-- Name: roles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);


--
-- Name: sso_configurations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_configurations ALTER COLUMN id SET DEFAULT nextval('public.sso_configurations_id_seq'::regclass);


--
-- Name: sso_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions ALTER COLUMN id SET DEFAULT nextval('public.sso_sessions_id_seq'::regclass);


--
-- Name: user_applications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_applications ALTER COLUMN id SET DEFAULT nextval('public.user_applications_id_seq'::regclass);


--
-- Name: user_custom_roles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_custom_roles ALTER COLUMN id SET DEFAULT nextval('public.user_custom_roles_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: activity_log activity_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activity_log
    ADD CONSTRAINT activity_log_pkey PRIMARY KEY (id);


--
-- Name: application_group_applications application_group_applications_application_group_id_application; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_group_applications
    ADD CONSTRAINT application_group_applications_application_group_id_application UNIQUE (application_group_id, application_id);


--
-- Name: application_group_applications application_group_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_group_applications
    ADD CONSTRAINT application_group_applications_pkey PRIMARY KEY (id);


--
-- Name: application_groups application_groups_organization_id_name_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_groups
    ADD CONSTRAINT application_groups_organization_id_name_unique UNIQUE (organization_id, name);


--
-- Name: application_groups application_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_groups
    ADD CONSTRAINT application_groups_pkey PRIMARY KEY (id);


--
-- Name: applications applications_client_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_client_id_unique UNIQUE (client_id);


--
-- Name: applications applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);


--
-- Name: authentication_logs authentication_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authentication_logs
    ADD CONSTRAINT authentication_logs_pkey PRIMARY KEY (id);


--
-- Name: cache_locks cache_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache_locks
    ADD CONSTRAINT cache_locks_pkey PRIMARY KEY (key);


--
-- Name: cache cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cache
    ADD CONSTRAINT cache_pkey PRIMARY KEY (key);


--
-- Name: custom_roles custom_roles_org_name_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_org_name_unique UNIQUE (organization_id, name);


--
-- Name: custom_roles custom_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_pkey PRIMARY KEY (id);


--
-- Name: failed_jobs failed_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.failed_jobs
    ADD CONSTRAINT failed_jobs_pkey PRIMARY KEY (id);


--
-- Name: failed_jobs failed_jobs_uuid_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.failed_jobs
    ADD CONSTRAINT failed_jobs_uuid_unique UNIQUE (uuid);


--
-- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


--
-- Name: invitations invitations_token_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_token_unique UNIQUE (token);


--
-- Name: job_batches job_batches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_batches
    ADD CONSTRAINT job_batches_pkey PRIMARY KEY (id);


--
-- Name: jobs jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);


--
-- Name: migrations migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migrations
    ADD CONSTRAINT migrations_pkey PRIMARY KEY (id);


--
-- Name: model_has_permissions model_has_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_has_permissions
    ADD CONSTRAINT model_has_permissions_pkey PRIMARY KEY (permission_id, model_id, model_type);


--
-- Name: model_has_roles model_has_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_has_roles
    ADD CONSTRAINT model_has_roles_pkey PRIMARY KEY (role_id, model_id, model_type);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: oauth_access_tokens oauth_access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_pkey PRIMARY KEY (id);


--
-- Name: oauth_auth_codes oauth_auth_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_auth_codes
    ADD CONSTRAINT oauth_auth_codes_pkey PRIMARY KEY (id);


--
-- Name: oauth_authorization_codes oauth_authorization_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_pkey PRIMARY KEY (id);


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: oauth_device_codes oauth_device_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_pkey PRIMARY KEY (id);


--
-- Name: oauth_device_codes oauth_device_codes_user_code_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_device_codes
    ADD CONSTRAINT oauth_device_codes_user_code_unique UNIQUE (user_code);


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_slug_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_unique UNIQUE (slug);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (email);


--
-- Name: permissions permissions_organization_id_name_guard_name_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_organization_id_name_guard_name_unique UNIQUE (organization_id, name, guard_name);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: role_has_permissions role_has_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_has_permissions
    ADD CONSTRAINT role_has_permissions_pkey PRIMARY KEY (permission_id, role_id);


--
-- Name: roles roles_organization_id_name_guard_name_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_organization_id_name_guard_name_unique UNIQUE (organization_id, name, guard_name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_configurations sso_configurations_application_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_configurations
    ADD CONSTRAINT sso_configurations_application_id_unique UNIQUE (application_id);


--
-- Name: sso_configurations sso_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_configurations
    ADD CONSTRAINT sso_configurations_pkey PRIMARY KEY (id);


--
-- Name: sso_sessions sso_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions
    ADD CONSTRAINT sso_sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_sessions sso_sessions_refresh_token_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions
    ADD CONSTRAINT sso_sessions_refresh_token_unique UNIQUE (refresh_token);


--
-- Name: sso_sessions sso_sessions_session_token_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions
    ADD CONSTRAINT sso_sessions_session_token_unique UNIQUE (session_token);


--
-- Name: user_applications user_applications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_applications
    ADD CONSTRAINT user_applications_pkey PRIMARY KEY (id);


--
-- Name: user_applications user_applications_user_id_application_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_applications
    ADD CONSTRAINT user_applications_user_id_application_id_unique UNIQUE (user_id, application_id);


--
-- Name: user_custom_roles user_custom_role_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_custom_roles
    ADD CONSTRAINT user_custom_role_unique UNIQUE (user_id, custom_role_id);


--
-- Name: user_custom_roles user_custom_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_custom_roles
    ADD CONSTRAINT user_custom_roles_pkey PRIMARY KEY (id);


--
-- Name: users users_email_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_unique UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: activity_log_log_name_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX activity_log_log_name_index ON public.activity_log USING btree (log_name);


--
-- Name: application_group_applications_application_group_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_group_applications_application_group_id_index ON public.application_group_applications USING btree (application_group_id);


--
-- Name: application_group_applications_application_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_group_applications_application_id_index ON public.application_group_applications USING btree (application_id);


--
-- Name: application_groups_organization_id_is_active_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_groups_organization_id_is_active_index ON public.application_groups USING btree (organization_id, is_active);


--
-- Name: application_groups_organization_id_parent_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_groups_organization_id_parent_id_index ON public.application_groups USING btree (organization_id, parent_id);


--
-- Name: application_groups_parent_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX application_groups_parent_id_index ON public.application_groups USING btree (parent_id);


--
-- Name: applications_client_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_client_id_index ON public.applications USING btree (client_id);


--
-- Name: applications_is_active_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_is_active_index ON public.applications USING btree (is_active);


--
-- Name: applications_organization_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_organization_id_index ON public.applications USING btree (organization_id);


--
-- Name: applications_passport_client_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX applications_passport_client_id_index ON public.applications USING btree (passport_client_id);


--
-- Name: apps_client_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX apps_client_active_idx ON public.applications USING btree (client_id, is_active);


--
-- Name: apps_org_active_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX apps_org_active_created_idx ON public.applications USING btree (organization_id, is_active, created_at);


--
-- Name: auth_logs_app_event_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_logs_app_event_created_idx ON public.authentication_logs USING btree (application_id, event, created_at);


--
-- Name: auth_logs_ip_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_logs_ip_created_idx ON public.authentication_logs USING btree (ip_address, created_at);


--
-- Name: auth_logs_success_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_logs_success_created_idx ON public.authentication_logs USING btree (success, created_at);


--
-- Name: auth_logs_user_event_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_logs_user_event_created_idx ON public.authentication_logs USING btree (user_id, event, created_at);


--
-- Name: authentication_logs_application_id_created_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX authentication_logs_application_id_created_at_index ON public.authentication_logs USING btree (application_id, created_at);


--
-- Name: authentication_logs_created_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX authentication_logs_created_at_index ON public.authentication_logs USING btree (created_at);


--
-- Name: authentication_logs_event_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX authentication_logs_event_index ON public.authentication_logs USING btree (event);


--
-- Name: authentication_logs_user_id_created_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX authentication_logs_user_id_created_at_index ON public.authentication_logs USING btree (user_id, created_at);


--
-- Name: causer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX causer ON public.activity_log USING btree (causer_type, causer_id);


--
-- Name: custom_roles_organization_id_is_active_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX custom_roles_organization_id_is_active_index ON public.custom_roles USING btree (organization_id, is_active);


--
-- Name: custom_roles_organization_id_is_system_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX custom_roles_organization_id_is_system_index ON public.custom_roles USING btree (organization_id, is_system);


--
-- Name: invitations_email_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_email_status_idx ON public.invitations USING btree (email, status);


--
-- Name: invitations_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_expires_at_index ON public.invitations USING btree (expires_at);


--
-- Name: invitations_expires_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_expires_status_idx ON public.invitations USING btree (expires_at, status);


--
-- Name: invitations_org_status_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_org_status_created_idx ON public.invitations USING btree (organization_id, status, created_at);


--
-- Name: invitations_organization_id_email_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_organization_id_email_index ON public.invitations USING btree (organization_id, email);


--
-- Name: invitations_token_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX invitations_token_index ON public.invitations USING btree (token);


--
-- Name: jobs_processing_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX jobs_processing_idx ON public.jobs USING btree (queue, reserved_at, available_at);


--
-- Name: jobs_queue_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX jobs_queue_index ON public.jobs USING btree (queue);


--
-- Name: model_has_permissions_model_id_model_type_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_has_permissions_model_id_model_type_index ON public.model_has_permissions USING btree (model_id, model_type);


--
-- Name: model_has_permissions_permission_model_type_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_has_permissions_permission_model_type_index ON public.model_has_permissions USING btree (organization_id, permission_id, model_id, model_type);


--
-- Name: model_has_permissions_team_foreign_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_has_permissions_team_foreign_key_index ON public.model_has_permissions USING btree (organization_id);


--
-- Name: model_has_roles_model_id_model_type_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_has_roles_model_id_model_type_index ON public.model_has_roles USING btree (model_id, model_type);


--
-- Name: model_has_roles_role_model_type_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_has_roles_role_model_type_index ON public.model_has_roles USING btree (organization_id, role_id, model_id, model_type);


--
-- Name: model_has_roles_team_foreign_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_has_roles_team_foreign_key_index ON public.model_has_roles USING btree (organization_id);


--
-- Name: notifications_notifiable_type_notifiable_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX notifications_notifiable_type_notifiable_id_index ON public.notifications USING btree (notifiable_type, notifiable_id);


--
-- Name: oauth_access_tokens_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_access_tokens_user_id_index ON public.oauth_access_tokens USING btree (user_id);


--
-- Name: oauth_auth_codes_revoked_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_auth_codes_revoked_expires_idx ON public.oauth_authorization_codes USING btree (revoked, expires_at);


--
-- Name: oauth_auth_codes_user_client_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_auth_codes_user_client_idx ON public.oauth_authorization_codes USING btree (user_id, client_id, revoked);


--
-- Name: oauth_auth_codes_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_auth_codes_user_id_index ON public.oauth_auth_codes USING btree (user_id);


--
-- Name: oauth_authorization_codes_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_authorization_codes_expires_at_index ON public.oauth_authorization_codes USING btree (expires_at);


--
-- Name: oauth_authorization_codes_user_id_client_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_authorization_codes_user_id_client_id_index ON public.oauth_authorization_codes USING btree (user_id, client_id);


--
-- Name: oauth_clients_owner_type_owner_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_clients_owner_type_owner_id_index ON public.oauth_clients USING btree (owner_type, owner_id);


--
-- Name: oauth_device_codes_client_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_device_codes_client_id_index ON public.oauth_device_codes USING btree (client_id);


--
-- Name: oauth_device_codes_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_device_codes_user_id_index ON public.oauth_device_codes USING btree (user_id);


--
-- Name: oauth_refresh_revoked_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_refresh_revoked_expires_idx ON public.oauth_refresh_tokens USING btree (revoked, expires_at);


--
-- Name: oauth_refresh_token_revoked_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_refresh_token_revoked_idx ON public.oauth_refresh_tokens USING btree (access_token_id, revoked);


--
-- Name: oauth_refresh_tokens_access_token_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_refresh_tokens_access_token_id_index ON public.oauth_refresh_tokens USING btree (access_token_id);


--
-- Name: oauth_tokens_client_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_tokens_client_created_idx ON public.oauth_access_tokens USING btree (client_id, created_at);


--
-- Name: oauth_tokens_revoked_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_tokens_revoked_expires_idx ON public.oauth_access_tokens USING btree (revoked, expires_at);


--
-- Name: oauth_tokens_user_valid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_tokens_user_valid_idx ON public.oauth_access_tokens USING btree (user_id, revoked, expires_at);


--
-- Name: organizations_is_active_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_is_active_index ON public.organizations USING btree (is_active);


--
-- Name: organizations_slug_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_slug_index ON public.organizations USING btree (slug);


--
-- Name: orgs_deleted_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orgs_deleted_active_idx ON public.organizations USING btree (deleted_at, is_active);


--
-- Name: orgs_slug_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orgs_slug_active_idx ON public.organizations USING btree (slug, is_active);


--
-- Name: permissions_team_foreign_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX permissions_team_foreign_key_index ON public.permissions USING btree (organization_id);


--
-- Name: roles_team_foreign_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX roles_team_foreign_key_index ON public.roles USING btree (organization_id);


--
-- Name: sessions_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_cleanup_idx ON public.sessions USING btree (last_activity, user_id);


--
-- Name: sessions_last_activity_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_last_activity_index ON public.sessions USING btree (last_activity);


--
-- Name: sessions_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_id_index ON public.sessions USING btree (user_id);


--
-- Name: sso_configurations_is_active_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_configurations_is_active_index ON public.sso_configurations USING btree (is_active);


--
-- Name: sso_sessions_app_analytics_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_app_analytics_idx ON public.sso_sessions USING btree (application_id, logged_out_at, created_at);


--
-- Name: sso_sessions_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_cleanup_idx ON public.sso_sessions USING btree (expires_at, logged_out_at);


--
-- Name: sso_sessions_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_expires_at_index ON public.sso_sessions USING btree (expires_at);


--
-- Name: sso_sessions_last_activity_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_last_activity_at_index ON public.sso_sessions USING btree (last_activity_at);


--
-- Name: sso_sessions_session_token_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_session_token_index ON public.sso_sessions USING btree (session_token);


--
-- Name: sso_sessions_user_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_user_active_idx ON public.sso_sessions USING btree (user_id, logged_out_at);


--
-- Name: sso_sessions_user_id_application_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_sessions_user_id_application_id_index ON public.sso_sessions USING btree (user_id, application_id);


--
-- Name: subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX subject ON public.activity_log USING btree (subject_type, subject_id);


--
-- Name: user_applications_application_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_applications_application_id_index ON public.user_applications USING btree (application_id);


--
-- Name: user_applications_last_login_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_applications_last_login_at_index ON public.user_applications USING btree (last_login_at);


--
-- Name: user_applications_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_applications_user_id_index ON public.user_applications USING btree (user_id);


--
-- Name: user_apps_app_last_login_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_apps_app_last_login_idx ON public.user_applications USING btree (application_id, last_login_at);


--
-- Name: user_apps_login_analytics_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_apps_login_analytics_idx ON public.user_applications USING btree (login_count, last_login_at);


--
-- Name: user_apps_user_granted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_apps_user_granted_idx ON public.user_applications USING btree (user_id, granted_at);


--
-- Name: user_custom_roles_custom_role_id_granted_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_custom_roles_custom_role_id_granted_at_index ON public.user_custom_roles USING btree (custom_role_id, granted_at);


--
-- Name: user_custom_roles_user_id_granted_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_custom_roles_user_id_granted_at_index ON public.user_custom_roles USING btree (user_id, granted_at);


--
-- Name: users_email_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_email_index ON public.users USING btree (email);


--
-- Name: users_is_active_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_is_active_index ON public.users USING btree (is_active);


--
-- Name: users_mfa_enabled_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_mfa_enabled_idx ON public.users USING btree (((mfa_methods IS NOT NULL)), is_active);


--
-- Name: users_org_active_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_org_active_created_idx ON public.users USING btree (organization_id, is_active, created_at);


--
-- Name: users_organization_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_organization_id_index ON public.users USING btree (organization_id);


--
-- Name: users_password_changed_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_password_changed_idx ON public.users USING btree (password_changed_at, is_active);


--
-- Name: users_provider_provider_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_provider_provider_id_index ON public.users USING btree (provider, provider_id);


--
-- Name: users_social_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_social_active_idx ON public.users USING btree (provider, provider_id, is_active);


--
-- Name: users_verified_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_verified_active_idx ON public.users USING btree (email_verified_at, is_active);


--
-- Name: application_group_applications application_group_applications_application_group_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_group_applications
    ADD CONSTRAINT application_group_applications_application_group_id_foreign FOREIGN KEY (application_group_id) REFERENCES public.application_groups(id) ON DELETE CASCADE;


--
-- Name: application_group_applications application_group_applications_application_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_group_applications
    ADD CONSTRAINT application_group_applications_application_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id) ON DELETE CASCADE;


--
-- Name: application_groups application_groups_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_groups
    ADD CONSTRAINT application_groups_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: application_groups application_groups_parent_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application_groups
    ADD CONSTRAINT application_groups_parent_id_foreign FOREIGN KEY (parent_id) REFERENCES public.application_groups(id) ON DELETE CASCADE;


--
-- Name: applications applications_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.applications
    ADD CONSTRAINT applications_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: authentication_logs authentication_logs_application_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authentication_logs
    ADD CONSTRAINT authentication_logs_application_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id);


--
-- Name: authentication_logs authentication_logs_user_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authentication_logs
    ADD CONSTRAINT authentication_logs_user_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: custom_roles custom_roles_created_by_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_created_by_foreign FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: custom_roles custom_roles_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: invitations invitations_accepted_by_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_accepted_by_foreign FOREIGN KEY (accepted_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: invitations invitations_cancelled_by_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_cancelled_by_foreign FOREIGN KEY (cancelled_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: invitations invitations_inviter_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_inviter_id_foreign FOREIGN KEY (inviter_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: invitations invitations_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: model_has_permissions model_has_permissions_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_has_permissions
    ADD CONSTRAINT model_has_permissions_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: model_has_permissions model_has_permissions_permission_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_has_permissions
    ADD CONSTRAINT model_has_permissions_permission_id_foreign FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;


--
-- Name: model_has_roles model_has_roles_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_has_roles
    ADD CONSTRAINT model_has_roles_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: model_has_roles model_has_roles_role_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_has_roles
    ADD CONSTRAINT model_has_roles_role_id_foreign FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: oauth_authorization_codes oauth_authorization_codes_client_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_client_id_foreign FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_authorization_codes oauth_authorization_codes_user_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_user_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_client_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_client_id_foreign FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id) ON DELETE CASCADE;


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_user_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_user_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: permissions permissions_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: role_has_permissions role_has_permissions_permission_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_has_permissions
    ADD CONSTRAINT role_has_permissions_permission_id_foreign FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;


--
-- Name: role_has_permissions role_has_permissions_role_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_has_permissions
    ADD CONSTRAINT role_has_permissions_role_id_foreign FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: roles roles_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: sso_configurations sso_configurations_application_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_configurations
    ADD CONSTRAINT sso_configurations_application_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id) ON DELETE CASCADE;


--
-- Name: sso_sessions sso_sessions_application_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions
    ADD CONSTRAINT sso_sessions_application_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id) ON DELETE CASCADE;


--
-- Name: sso_sessions sso_sessions_logged_out_by_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions
    ADD CONSTRAINT sso_sessions_logged_out_by_foreign FOREIGN KEY (logged_out_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: sso_sessions sso_sessions_user_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_sessions
    ADD CONSTRAINT sso_sessions_user_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_applications user_applications_application_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_applications
    ADD CONSTRAINT user_applications_application_id_foreign FOREIGN KEY (application_id) REFERENCES public.applications(id) ON DELETE CASCADE;


--
-- Name: user_applications user_applications_granted_by_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_applications
    ADD CONSTRAINT user_applications_granted_by_foreign FOREIGN KEY (granted_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_applications user_applications_user_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_applications
    ADD CONSTRAINT user_applications_user_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_custom_roles user_custom_roles_custom_role_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_custom_roles
    ADD CONSTRAINT user_custom_roles_custom_role_id_foreign FOREIGN KEY (custom_role_id) REFERENCES public.custom_roles(id) ON DELETE CASCADE;


--
-- Name: user_custom_roles user_custom_roles_granted_by_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_custom_roles
    ADD CONSTRAINT user_custom_roles_granted_by_foreign FOREIGN KEY (granted_by) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_custom_roles user_custom_roles_user_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_custom_roles
    ADD CONSTRAINT user_custom_roles_user_id_foreign FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users users_organization_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_organization_id_foreign FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database dump
--

-- Dumped from database version 16.9 (Homebrew)
-- Dumped by pg_dump version 16.9 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: migrations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.migrations (id, migration, batch) FROM stdin;
1	0001_01_01_000001_create_cache_table	1
2	0001_01_01_000002_create_jobs_table	1
3	2025_08_24_100000_create_organizations_table	1
4	2025_08_24_100001_create_users_table	1
5	2025_08_24_100002_create_applications_table	1
6	2025_08_24_100003_create_user_applications_table	1
7	2025_08_24_100004_create_authentication_logs_table	1
8	2025_08_24_100006_create_activity_log_table	1
9	2025_08_24_185632_create_oauth_auth_codes_table	1
10	2025_08_24_185633_create_oauth_access_tokens_table	1
11	2025_08_24_185634_create_oauth_refresh_tokens_table	1
12	2025_08_24_185635_create_oauth_clients_table	1
13	2025_08_24_185636_create_oauth_device_codes_table	1
14	2025_08_24_185642_create_permission_tables	1
15	2025_08_24_203344_create_notifications_table	1
16	2025_09_02_215034_create_invitations_table	1
17	2025_09_02_215946_create_sso_sessions_table	1
18	2025_09_02_221638_create_application_groups_table	1
19	2025_09_02_223129_create_custom_roles_table	1
20	2025_09_02_223238_create_user_custom_roles_table	1
21	2025_09_03_080105_create_application_group_applications_table	1
22	2025_09_08_120005_create_sso_configurations_table	1
23	2025_09_09_120422_add_deleted_at_to_organizations_table	1
24	2025_09_10_105140_create_oauth_authorization_codes_table	1
25	2025_09_10_214300_add_performance_indexes_to_database	1
26	2025_09_12_100637_add_passport_client_id_to_applications_table	1
27	2025_09_17_175951_add_scopes_to_applications_table	1
28	2025_09_17_193217_add_user_id_and_client_id_to_oauth_refresh_tokens_table	1
\.


--
-- Name: migrations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.migrations_id_seq', 28, true);


--
-- PostgreSQL database dump complete
--

