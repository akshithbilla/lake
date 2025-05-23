import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import DefaultLayout from "@/layouts/default";
import ProjectForm from '../dashboard/ProjectForm';
import ProjectList from '../dashboard/ProjectList';
import ProfileForm from '../dashboard/ProfileForm';
import TemplateSelector from '../dashboard/TemplateSelector';
import { 
  ArrowTopRightOnSquareIcon,
  PlusIcon,
  FolderIcon,
  UserCircleIcon,
  Squares2X2Icon,
  SparklesIcon,
  LinkIcon,
  CogIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';

// Default profile structure
const defaultProfile = {
  username: '',
  projects: [],
  template: 'default',
  stats: {
    totalProjects: 0
  }
};

export default function IndexPage() {
  const [profile, setProfile] = useState(defaultProfile);
  const [activeTab, setActiveTab] = useState('projects');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [usernameInput, setUsernameInput] = useState('');
  const [isGeneratingSite, setIsGeneratingSite] = useState(false);
  const [siteGenerated, setSiteGenerated] = useState(false);
  const navigate = useNavigate();

  const fetchProfile = async () => {
    try {
      setIsLoading(true);
      setError(null);

      // First check authentication status
      const authCheck = await fetch(`${process.env.BACKEND_URL}/check-auth`, {
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!authCheck.ok) {
        if (authCheck.status === 401) {
          navigate('/login');
          return;
        }
        throw new Error(`Auth check failed with status ${authCheck.status}`);
      }

      const authData = await authCheck.json();
      if (!authData.authenticated) {
        navigate('/login');
        return;
      }

      // Then fetch profile data
      const profileRes = await fetch(`${process.env.BACKEND_URL}/api/profiles/me`, {
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!profileRes.ok) {
        if (profileRes.status === 404) {
          setActiveTab('setup');
          return;
        }
        throw new Error('Failed to fetch profile');
      }

      const profileData = await profileRes.json();
      setProfile({
        ...defaultProfile,
        ...profileData,
        projects: Array.isArray(profileData.projects) ? profileData.projects : [],
        stats: {
          totalProjects: Array.isArray(profileData.projects) ? profileData.projects.length : 0
        }
      });

    } catch (err) {
      console.error('Profile fetch error:', err);
      setError(err.message);
      
      if (err.message.includes('401') || err.message.includes('auth')) {
        navigate('/login');
      } else {
        setActiveTab('setup');
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  const handleCreateProfile = async (username) => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Check username availability
      const checkRes = await fetch(
        `${process.env.BACKEND_URL}/api/profiles/check-username?username=${encodeURIComponent(username)}`,
        { credentials: 'include' }
      );
      
      if (!checkRes.ok) throw new Error('Failed to check username');
      
      const checkData = await checkRes.json();
      if (checkData.exists) throw new Error('Username already taken');
      
      // Create profile
      const res = await fetch(`${process.env.BACKEND_URL}/api/profiles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
        credentials: 'include'
      });
      
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.message || 'Failed to create profile');
      }

      const data = await res.json();
      setProfile({
        ...defaultProfile,
        ...data,
        projects: Array.isArray(data.projects) ? data.projects : [],
        stats: {
          totalProjects: Array.isArray(data.projects) ? data.projects.length : 0
        }
      });
      setActiveTab('projects');
    } catch (err) {
      console.error('Profile creation error:', err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGenerateSite = async () => {
    try {
      setIsGeneratingSite(true);
      setError(null);
      await new Promise(resolve => setTimeout(resolve, 1500));
      setSiteGenerated(true);
    } catch (err) {
      console.error('Site generation error:', err);
      setError('Failed to generate site');
    } finally {
      setIsGeneratingSite(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  if (error && activeTab !== 'setup') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-xl shadow-md max-w-md w-full text-center">
          <div className="bg-red-100 p-3 rounded-full w-12 h-12 flex items-center justify-center mx-auto">
            <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h3 className="text-lg font-medium text-gray-900 mt-4">Error loading dashboard</h3>
          <p className="text-gray-600 mt-2">{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="mt-6 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  if (!profile.username || activeTab === 'setup') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-purple-50 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white rounded-2xl shadow-xl p-8 border border-gray-100">
          <div className="text-center mb-6">
            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 mb-4">
              <SparklesIcon className="h-6 w-6 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900">Welcome!</h1>
            <p className="text-gray-600 mt-2">Set up your profile to get started</p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-lg text-sm">
              {error}
            </div>
          )}

          <form 
            onSubmit={(e) => {
              e.preventDefault();
              const username = e.target.username.value.trim();
              if (username) handleCreateProfile(username);
            }}
            className="space-y-6"
          >
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                Choose your username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                minLength="3"
                maxLength="20"
                pattern="[a-zA-Z0-9]+"
                title="Only letters and numbers are allowed"
                className="w-full px-4 py-3 border border-gray-200 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                placeholder="username"
                value={usernameInput}
                onChange={(e) => setUsernameInput(e.target.value)}
              />
              <p className="mt-1 text-xs text-gray-500">3-20 characters, letters and numbers only</p>
              
              {usernameInput && (
                <div className="mt-2 flex items-center text-sm text-gray-600">
                  <LinkIcon className="h-4 w-4 mr-1" />
                  <span>Your site will be: </span>
                  <span className="ml-1 font-medium text-blue-600">
                    {window.location.origin}/{usernameInput}
                  </span>
                </div>
              )}
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center px-6 py-3 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all disabled:opacity-70"
            >
              {isLoading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Creating...
                </>
              ) : (
                <>
                  <PlusIcon className="h-5 w-5 mr-2" />
                  Create Profile
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <DefaultLayout>
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header Section */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
            <div className="mb-4 md:mb-0">
              {/* Steps Guide */}
              <div className="mb-4 bg-white p-4 rounded-lg shadow-sm border border-gray-100">
                <h3 className="text-sm font-medium text-gray-500 mb-3">HOW TO CREATE YOUR SITE</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                  <div className={`flex items-start ${activeTab === 'projects' ? 'text-blue-600' : 'text-gray-600'}`}>
                    <div className={`flex-shrink-0 h-5 w-5 mr-2 ${activeTab === 'projects' ? 'text-blue-500' : 'text-gray-400'}`}>
                      {profile.projects?.length > 0 ? (
                        <CheckCircleIcon className="h-5 w-5" />
                      ) : (
                        <span className="inline-flex items-center justify-center h-5 w-5 rounded-full border-2 border-current">
                          <span className="text-xs">1</span>
                        </span>
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium">Add Projects</p>
                      <p className="text-xs text-gray-500">Fill your portfolio content</p>
                    </div>
                  </div>
                  <div className={`flex items-start ${activeTab === 'profile' ? 'text-blue-600' : 'text-gray-600'}`}>
                    <div className={`flex-shrink-0 h-5 w-5 mr-2 ${activeTab === 'profile' ? 'text-blue-500' : 'text-gray-400'}`}>
                      {profile.username ? (
                        <CheckCircleIcon className="h-5 w-5" />
                      ) : (
                        <span className="inline-flex items-center justify-center h-5 w-5 rounded-full border-2 border-current">
                          <span className="text-xs">2</span>
                        </span>
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium">Profile Info</p>
                      <p className="text-xs text-gray-500">Add your personal details</p>
                    </div>
                  </div>
                  <div className={`flex items-start ${activeTab === 'template' ? 'text-blue-600' : 'text-gray-600'}`}>
                    <div className={`flex-shrink-0 h-5 w-5 mr-2 ${activeTab === 'template' ? 'text-blue-500' : 'text-gray-400'}`}>
                      {profile.template ? (
                        <CheckCircleIcon className="h-5 w-5" />
                      ) : (
                        <span className="inline-flex items-center justify-center h-5 w-5 rounded-full border-2 border-current">
                          <span className="text-xs">3</span>
                        </span>
                      )}
                    </div>
                    <div>
                      <p className="text-sm font-medium">Choose Template</p>
                      <p className="text-xs text-gray-500">Select your preferred design</p>
                    </div>
                  </div>
                  <div className="flex items-start text-gray-600">
                    <div className="flex-shrink-0 h-5 w-5 mr-2 text-gray-400">
                      <span className="inline-flex items-center justify-center h-5 w-5 rounded-full border-2 border-current">
                        <span className="text-xs">4</span>
                      </span>
                    </div>
                    <div>
                      <p className="text-sm font-medium">View Your Site</p>
                      <p className="text-xs text-gray-500">Publish and share your portfolio</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <h2 className="text-lg font-semibold text-gray-600">Dashboard</h2>
              <div className="flex items-center mt-1">
                <h1 className="text-3xl font-bold text-gray-900">My Projects</h1>
                <span className="ml-3 px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                  {profile.projects?.length || 0} {profile.projects?.length === 1 ? 'project' : 'projects'}
                </span>
              </div>
            </div>
            <button
              onClick={siteGenerated ? () => window.open(`/${profile.username}`, '_blank') : handleGenerateSite}
              disabled={isGeneratingSite}
              className="inline-flex items-center px-5 py-2.5 border border-transparent text-sm font-medium rounded-lg shadow-sm text-white bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all disabled:opacity-70"
            >
              {isGeneratingSite ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Generating...
                </>
              ) : siteGenerated ? (
                <>
                  <ArrowTopRightOnSquareIcon className="h-5 w-5 mr-2" />
                  View My Site
                </>
              ) : (
                <>
                  <SparklesIcon className="h-5 w-5 mr-2" />
                  Generate My Site
                </>
              )}
            </button>
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
            <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
              <div className="flex items-center">
                <div className="p-3 rounded-lg bg-blue-50 text-blue-600 mr-4">
                  <FolderIcon className="h-6 w-6" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Total Projects</p>
                  <p className="text-2xl font-semibold text-gray-900">
                    {profile.projects?.length || 0}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
              <div className="flex items-center">
                <div className="p-3 rounded-lg bg-purple-50 text-purple-600 mr-4">
                  <UserCircleIcon className="h-6 w-6" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Profile Name</p>
                  <p className="text-2xl font-semibold text-gray-900">
                    {profile.username}
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
              <div className="flex items-center">
                <div className="p-3 rounded-lg bg-green-50 text-green-600 mr-4">
                  <Squares2X2Icon className="h-6 w-6" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Current Template</p>
                  <p className="text-2xl font-semibold text-gray-900 capitalize">
                    {profile.template || 'default'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="mb-6">
            <nav className="flex space-x-4">
              <button
                onClick={() => setActiveTab('projects')}
                className={`${activeTab === 'projects' ? 'bg-blue-100 text-blue-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'} px-4 py-2 rounded-lg font-medium text-sm flex items-center transition-all`}
              >
                <FolderIcon className="h-5 w-5 mr-2" />
                Projects
              </button>
              <button
                onClick={() => setActiveTab('profile')}
                className={`${activeTab === 'profile' ? 'bg-blue-100 text-blue-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'} px-4 py-2 rounded-lg font-medium text-sm flex items-center transition-all`}
              >
                <UserCircleIcon className="h-5 w-5 mr-2" />
                Profile
              </button>
              <button
                onClick={() => setActiveTab('template')}
                className={`${activeTab === 'template' ? 'bg-blue-100 text-blue-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'} px-4 py-2 rounded-lg font-medium text-sm flex items-center transition-all`}
              >
                <Squares2X2Icon className="h-5 w-5 mr-2" />
                Template
              </button>
            </nav>
          </div>

          {/* Tab Content */}
          <div className="space-y-6">
            {activeTab === 'projects' && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-1">
                  <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 h-full hover:shadow-md transition-shadow">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                      <PlusIcon className="h-5 w-5 mr-2 text-blue-600" />
                      Add New Project
                    </h3>
                    <ProjectForm 
                      onProjectAdded={(newProject) => {
                        setProfile(prev => ({
                          ...prev,
                          projects: [...(prev.projects || []), newProject],
                          stats: {
                            totalProjects: (prev.projects?.length || 0) + 1
                          }
                        }));
                      }}
                    />
                  </div>
                </div>
                <div className="lg:col-span-2">
                  <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-6">
                      <h3 className="text-lg font-semibold text-gray-900">Your Projects</h3>
                      <div className="relative">
                        <select className="appearance-none bg-gray-50 border border-gray-200 text-gray-700 py-2 px-3 pr-8 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm">
                          <option>All Projects</option>
                          <option>Active</option>
                          <option>Archived</option>
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700">
                          <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                            <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z"/>
                          </svg>
                        </div>
                      </div>
                    </div>
                    <ProjectList 
                      projects={profile.projects || []}
                      onProjectUpdated={(updatedProject) => {
                        setProfile(prev => ({
                          ...prev,
                          projects: (prev.projects || []).map(p => 
                            p._id === updatedProject._id ? updatedProject : p
                          )
                        }));
                      }}
                      onProjectDeleted={(projectId) => {
                        setProfile(prev => ({
                          ...prev,
                          projects: (prev.projects || []).filter(p => p._id !== projectId),
                          stats: {
                            totalProjects: (prev.projects?.length || 0) - 1
                          }
                        }));
                      }}
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'profile' && (
              <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                <div className="flex items-center mb-6">
                  <div className="p-3 rounded-lg bg-blue-50 text-blue-600 mr-4">
                    <UserCircleIcon className="h-6 w-6" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900">Profile Settings</h3>
                </div>
                <ProfileForm 
                  profile={profile}
                  onProfileUpdated={(updatedProfile) => {
                    setProfile(prev => ({
                      ...prev,
                      ...updatedProfile
                    }));
                  }}
                />
              </div>
            )}

            {activeTab === 'template' && (
              <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                <div className="flex items-center mb-6">
                  <div className="p-3 rounded-lg bg-purple-50 text-purple-600 mr-4">
                    <Squares2X2Icon className="h-6 w-6" />
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900">Template Selection</h3>
                </div>
                <TemplateSelector 
                  currentTemplate={profile.template || 'default'}
                  onTemplateSelected={(template) => {
                    setProfile(prev => ({ 
                      ...prev, 
                      template 
                    }));
                  }}
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </DefaultLayout>
  );
}